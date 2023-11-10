open Mirage

(* uTCP *)

let tcpv4v6_direct_conf id =
  let packages_v = Key.pure [ package "utcp" ~sublibs:[ "mirage" ] ] in
  let connect _ modname = function
    | [_random; _mclock; _time; ip] ->
      Fmt.str "Lwt.return (%s.connect %S %s)" modname id ip
    | _ -> failwith "direct tcpv4v6"
  in
  impl ~packages_v ~connect "Utcp_mirage.Make"
    (random @-> mclock @-> time @-> ipv4v6 @-> (tcp: 'a tcp typ))

let direct_tcpv4v6
    ?(clock=default_monotonic_clock)
    ?(random=default_random)
    ?(time=default_time) id ip =
  tcpv4v6_direct_conf id $ random $ clock $ time $ ip

let net =
  let ethernet = etif default_network in
  let arp = arp ethernet in
  let i4 = create_ipv4 ethernet arp in
  let i6 = create_ipv6 default_network ethernet in
  let i4i6 = create_ipv4v6 i4 i6 in
  let tcpv4v6 = direct_tcpv4v6 "service" i4i6 in
  let ipv4_only = Runtime_key.ipv4_only () in
  let ipv6_only = Runtime_key.ipv6_only () in
  direct_stackv4v6 ~tcp:tcpv4v6 ~ipv4_only ~ipv6_only default_network ethernet arp i4 i6

let enable_monitoring =
  let doc = Cmdliner.Arg.info
      ~doc:"Enable monitoring (only available for solo5 targets)"
      [ "enable-monitoring" ]
  in
  Key.(create "enable-monitoring" Arg.(flag doc))

let management_stack =
  if_impl
    (Key.value enable_monitoring)
    (generic_stackv4v6 ~group:"management" (netif ~group:"management" "management"))
    net

let (name : string Runtime_key.key) = Runtime_key.create "Unikernel.K.name"

let monitoring =
  let monitor = Runtime_key.create "Unikernel.K.monitor" in
  let connect _ modname = function
    | [ _ ; _ ; stack ] ->
      Fmt.str "Lwt.return (match %a with\
               | None -> Logs.warn (fun m -> m \"no monitor specified, not outputting statistics\")\
               | Some ip -> %s.create ip ~hostname:%a %s)"
        Runtime_key.call monitor modname
        Runtime_key.call name stack
    | _ -> assert false
  in
  impl
    ~packages:[ package "mirage-monitoring" ]
    ~runtime_keys:[ Runtime_key.v name ; Runtime_key.v monitor ]
    ~connect "Mirage_monitoring.Make"
    (time @-> pclock @-> stackv4v6 @-> job)

let syslog =
  let syslog = Runtime_key.create "Unikernel.K.syslog" in
  let connect _ modname = function
    | [ _ ; stack ] ->
      Fmt.str "Lwt.return (match %a with\
               | None -> Logs.warn (fun m -> m \"no syslog specified, dumping on stdout\")\
               | Some ip -> Logs.set_reporter (%s.create %s ip ~hostname:%a ()))"
        Runtime_key.call syslog modname stack
        Runtime_key.call name
    | _ -> assert false
  in
  impl
    ~packages:[ package ~sublibs:["mirage"] ~min:"0.4.0" "logs-syslog" ]
    ~runtime_keys:[ Runtime_key.v name ; Runtime_key.v syslog ]
    ~connect "Logs_syslog_mirage.Udp"
    (pclock @-> stackv4v6 @-> job)

type i0 = I0
let i0 = Functoria.Type.v I0
let no0 = Functoria.impl "Int" job

type n1 = N1
let n1 = Functoria.Type.v N1
let noop1 = Functoria.impl "Set.Make" (job @-> job)

let optional_monitoring time pclock stack =
  if_impl (Key.value enable_monitoring)
    (monitoring $ time $ pclock $ stack)
    (noop1 $ no0)

let optional_syslog pclock stack =
  if_impl (Key.value enable_monitoring)
    (syslog $ pclock $ stack)
    (noop1 $ no0)

let packages = [
  package "logs" ;
  package "cmarkit" ;
  package ~min:"3.7.1" "tcpip" ;
  package ~min:"6.1.1" ~sublibs:["mirage"] "dns-certify";
  package "tls-mirage";
  package ~min:"4.3.1" "mirage-runtime";
]

let retreat =
  foreign
    ~packages
    "Unikernel.Main"
    (random @-> time @-> pclock @-> stackv4v6 @-> job)

let () =
  register "retreat" [
    optional_syslog default_posix_clock management_stack ;
    optional_monitoring default_time default_posix_clock management_stack ;
    retreat $ default_random $ default_time $ default_posix_clock $ net ;
  ]
