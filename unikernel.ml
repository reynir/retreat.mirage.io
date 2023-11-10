open Lwt.Infix

module K = struct
  open Cmdliner

  let ip =
    Arg.conv ~docv:"IP" (Ipaddr.of_string, Ipaddr.pp)

  let key =
    Arg.conv ~docv:"HOST:HASH:DATA" Dns.Dnskey.(name_key_of_string, pp_name_key)

  let dns_key =
    let doc = Arg.info ~doc:"nsupdate key (name:type:value,...)" ["dns-key"] in
    Arg.(value & opt (some string) None doc) |> Mirage_runtime.key

  let dns_server =
    let doc = Arg.info ~doc:"dns server IP" ["dns-server"] in
    Arg.(value & opt (some ip) None doc) |> Mirage_runtime.key

  let dns_port =
    let doc = Arg.info ~doc:"dns server port" ["dns-port"] in
    Arg.(value & opt int 53 doc) |> Mirage_runtime.key

  let key =
    let doc = Arg.info ~doc:"certificate key (<type>:seed or b64)" ["key"] in
    Arg.(value & opt (some string) None doc) |> Mirage_runtime.key

  let no_tls =
    let doc = Arg.info ~doc:"Disable TLS" [ "no-tls" ] in
    Arg.(value & flag doc) |> Mirage_runtime.key

  let name =
    let doc = Arg.info ~doc:"Name of the unikernel" [ "name" ] in
    Arg.(value & opt string "a.ns.robur.coop" doc)

  let hostname = name |> Mirage_runtime.key

  let monitor =
    let doc = Arg.info ~doc:"monitor host IP" [ "monitor" ] in
    Arg.(value & opt (some ip) None doc)

  let syslog =
    let doc = Arg.info ~doc:"syslog host IP" [ "syslog" ] in
    Arg.(value & opt (some ip) None doc)
end

module Main (R : Mirage_random.S) (T : Mirage_time.S) (P : Mirage_clock.PCLOCK) (S : Tcpip.Stack.V4V6) = struct
  module Dns_certify = Dns_certify_mirage.Make(R)(P)(T)(S)
  module TLS = Tls_mirage.Make(S.TCP)

  let http_header ~status xs =
    let headers = List.map (fun (k, v) -> k ^ ": " ^ v) xs in
    let lines = status :: headers @ [ "\r\n" ] in
    Cstruct.of_string (String.concat "\r\n" lines)

  let header len = http_header
      ~status:"HTTP/1.1 200 OK"
      [ ("Content-Type", "text/html; charset=UTF-8") ;
        ("Content-length", string_of_int len) ;
        ("Connection", "close") ]

  let incr_access =
    let s = ref 0 in
    let open Metrics in
    let doc = "access statistics" in
    let data () =
      Data.v [
        int "total http responses" !s ;
      ] in
    let src = Src.v ~doc ~tags:Tags.[] ~data "http" in
    (fun () ->
       s := succ !s;
       Metrics.add src (fun x -> x) (fun d -> d ()))

  let serve data tcp =
    incr_access ();
    S.TCP.writev tcp data >>= fun _ ->
    S.TCP.close tcp

  let serve_tls cfg data tcp_flow =
    incr_access ();
    TLS.server_of_flow cfg tcp_flow >>= function
    | Ok tls_flow ->
      TLS.writev tls_flow data >>= fun _ ->
      TLS.close tls_flow
    | Error e ->
      Logs.warn (fun m -> m "TLS error %a" TLS.pp_write_error e);
      S.TCP.close tcp_flow

  let start _random _time _pclock stack =
    let data =
      let content_size = Cstruct.length Page.rendered in
      [ header content_size ; Page.rendered ]
    in
    (if not (K.no_tls ()) then
       match
         let ( let* ) = Result.bind in
         let* hostname = Domain_name.of_string (K.hostname ()) in
         let* hostname = Domain_name.host hostname in
         let* key = Option.to_result ~none:(`Msg "no key provided") (K.key ()) in
         let* key_type, key_data, key_seed =
           match String.split_on_char ':' key with
           | [ typ ; data ] ->
             let* typ = X509.Key_type.of_string typ in
             (match typ with
              | `RSA -> Ok (`RSA, None, Some data)
              | x -> Ok (x, Some data, None))
           | _ ->
             Error (`Msg "expected format of key is type:data")
         in
         let* dns_key = Option.to_result ~none:(`Msg "DNS key is missing") (K.dns_key ()) in
         let* dns_server = Option.to_result ~none:(`Msg "DNS server is missing") (K.dns_server ()) in
         let dns_port = K.dns_port () in
         Ok (dns_key, hostname, key_type, key_data, key_seed, dns_server, dns_port)
       with
       | Error (`Msg msg) ->
           Logs.err (fun m -> m "error while parsing parameters: %s" msg);
           exit Mirage_runtime.argument_error
       | Ok (dns_key, hostname, key_type, key_data, key_seed, dns_server, dns_port) ->
         Dns_certify.retrieve_certificate
           stack ~dns_key ~hostname ~key_type ?key_data ?key_seed
           dns_server dns_port >|= function
         | Error (`Msg msg) ->
           Logs.err (fun m -> m "error while requesting certificate: %s" msg);
           exit Mirage_runtime.argument_error
         | Ok certificates ->
           let certificates = `Single certificates in
           let tls_config = Tls.Config.server ~certificates () in
           S.TCP.listen (S.tcp stack) ~port:443 (serve_tls tls_config data)
     else
       Lwt.return_unit) >>= fun () ->
    S.TCP.listen (S.tcp stack) ~port:80 (serve data) ;
    S.listen stack
end
