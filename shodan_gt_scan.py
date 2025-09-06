#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
from collections import defaultdict
from datetime import datetime

try:
    from dotenv import load_dotenv
    from shodan import Shodan, APIError
except ImportError:
    print("Faltan dependencias. Ejecuta: pip install shodan python-dotenv")
    sys.exit(1)


def parse_args():
    p = argparse.ArgumentParser(
        description=(
            "CLI para consultas a Shodan enfocadas en Guatemala.\n"
            "Modo SEARCH (cumple consigna): usa filtros como city:\"Jalapa\" + country:\"GT\".\n"
            "Modo HOST (fallback sin créditos): lee IPs de archivo y usa api.host(IP)."
        )
    )
    # Datos estudiante (requeridos por consigna)
    p.add_argument("--carne", required=True, help="Número de carné.")
    p.add_argument("--nombre", required=True, help="Nombre completo.")
    p.add_argument("--curso", required=True, help="Curso.")
    p.add_argument("--seccion", required=True, help="Sección.")

    # Modo de operación
    p.add_argument(
        "--mode",
        choices=["search", "host"],
        default="search",
        help="search = usa filtros; host = fallback por IPs (sin créditos de búsqueda).",
    )

    # SEARCH
    p.add_argument(
        "--filter",
        help="Filtro Shodan (EJ: 'city:\"Jalapa\"', 'port:3389', 'product:\"Apache httpd\"'). "
             "Prohibido org:. country:\"GT\" se agrega automáticamente."
    )
    p.add_argument("--query", default="", help="(Opcional) términos libres (p.ej. 'ssl').")
    p.add_argument("--max-pages", type=int, default=3, help="Páginas a paginar en search (≈100 resultados/página).")

    # HOST fallback
    p.add_argument("--ip-file", help="Archivo con IPs (una por línea) para modo host o como fallback.")
    p.add_argument("--gt-only", action="store_true", help="En modo host, filtra solo hosts con country_code == 'GT'.")

    # Utilidad
    p.add_argument("--diagnose", action="store_true", help="Muestra plan y créditos de la cuenta Shodan.")
    p.add_argument("--verbose", action="store_true", help="Salida detallada por resultado.")
    return p.parse_args()


def mask_key(k: str) -> str:
    if not k:
        return ""
    if len(k) <= 8:
        return "*" * (len(k) - 4) + k[-4:]
    return k[:4] + "*" * (len(k) - 8) + k[-4:]


def print_header(args, context_line: str):
    print("=" * 80)
    print("CONSULTA SHODAN - GUATEMALA")
    print(f"Fecha/Hora: {datetime.now().isoformat(timespec='seconds')}")
    print("-" * 80)
    print(f"Número de carné : {args.carne}")
    print(f"Nombre completo  : {args.nombre}")
    print(f"Curso            : {args.curso}")
    print(f"Sección          : {args.seccion}")
    print("-" * 80)
    print(context_line)
    print("=" * 80)
    print()


def diagnose(api: Shodan, api_key: str):
    print("=" * 80)
    print("DIAGNÓSTICO DE API")
    print("-" * 80)
    print(f"SHODAN_API_KEY (enmasc.): {mask_key(api_key)}")
    try:
        info = api.info()
        plan = info.get("plan")
        q_credits = info.get("query_credits")
        s_credits = info.get("scan_credits")
        print(f"Plan          : {plan}")
        print(f"Query credits : {q_credits}")
        print(f"Scan credits  : {s_credits}")
        if q_credits is not None and q_credits <= 0:
            print("Aviso: query_credits=0 → api.search dará 403 (sin créditos de búsqueda).")
        if plan in ("free", "dev", "internetdb", "oss"):
            print("Aviso: tu plan puede no incluir búsqueda completa (api.search).")
    except APIError as e:
        print("No fue posible obtener info de la cuenta:", e)
    print("=" * 80)
    print()


def print_match_from_search(m: dict, args, unique_ips: set, port_to_ips: dict):
    ip = m.get("ip_str") or m.get("ip")
    port = m.get("port")
    transport = m.get("transport")
    product = m.get("product") or (m.get("http", {}) or {}).get("server")
    org = m.get("org")
    hostnames = m.get("hostnames") or []
    asn = m.get("asn")
    city = (m.get("location") or {}).get("city")
    data_snippet = (m.get("data") or "").strip()

    if ip:
        unique_ips.add(ip)
        if port is not None:
            port_to_ips[port].add(ip)

    print("-" * 80)
    print(f"IP        : {ip}")
    print(f"Puerto    : {port} ({transport})" if transport else f"Puerto    : {port}")
    print(f"Producto  : {product}")
    print(f"ASN       : {asn}")
    print(f"Ciudad    : {city}")
    print(f"Org       : {org}")
    print(f"Hostnames : {', '.join(hostnames) if hostnames else '(sin hostnames)'}")
    if data_snippet:
        preview = data_snippet if len(data_snippet) <= 500 else data_snippet[:500] + "..."
        print("Banner/Extracto:")
        print(preview)
    if args.verbose:
        print("RAW keys:", list(m.keys())[:15], "...")


def print_match_from_host(host: dict, entry: dict, args, unique_ips: set, port_to_ips: dict):
    m = {
        "ip_str": host.get("ip_str"),
        "ip": host.get("ip"),
        "port": entry.get("port"),
        "transport": entry.get("transport"),
        "product": entry.get("product"),
        "org": host.get("org"),
        "hostnames": host.get("hostnames"),
        "asn": host.get("asn"),
        "location": {"city": (entry.get("location") or {}).get("city") if isinstance(entry.get("location"), dict) else host.get("city")},
        "data": entry.get("data"),
        "http": entry.get("http"),
        "isp": host.get("isp"),
        "os": host.get("os"),
        "vulns": entry.get("vulns"),
    }
    print_match_from_search(m, args, unique_ips, port_to_ips)


def summary_block(unique_ips: set, port_to_ips: dict, args):
    print()
    print("=" * 80)
    print("RESUMEN")
    print("-" * 80)
    print(f"Total de direcciones IP únicas identificadas: {len(unique_ips)}")
    print()
    print("Total de IPs por puerto abierto (conteo de IPs únicas por puerto):")
    if port_to_ips:
        for port, ips in sorted(port_to_ips.items(), key=lambda kv: len(kv[1]), reverse=True):
            print(f"  - Puerto {port}: {len(ips)} IP(s)")
    else:
        print("  (No se identificaron puertos en los resultados)")
    print("-" * 80)
    print(f"Número de carné : {args.carne}")
    print(f"Nombre completo  : {args.nombre}")
    print(f"Curso            : {args.curso}")
    print(f"Sección          : {args.seccion}")
    print("=" * 80)


def run_search(api: Shodan, args) -> int:
    if not args.filter:
        print("Debes proporcionar --filter en modo search. Ej: --filter 'city:\"Jalapa\" port:3389'")
        return 2
    if "org:" in args.filter.lower():
        print("El filtro contiene 'org:' y la consigna lo prohíbe. Usa otro filtro.")
        return 2

    parts = ['country:"GT"', args.filter.strip()]
    if args.query.strip():
        parts.append(args.query.strip())
    query = " ".join(parts)

    print_header(args, f"Consulta (search): {query}")

    unique_ips = set()
    port_to_ips = defaultdict(set)

    try:
        res = api.search(query, page=1)
        matches = res.get("matches", []) or []
        total = res.get("total", 0)

        if not matches:
            print("No se encontraron resultados en la primera página.")
        else:
            for m in matches:
                print_match_from_search(m, args, unique_ips, port_to_ips)

        print("-" * 80)
        print(f"[Página 1] Resultados: {len(matches)} | Total reportado por Shodan: {total}")
        print("-" * 80)

        # Paginación adicional
        shown = len(matches)
        page = 2
        while shown < total and page <= args.max_pages:
            res = api.search(query, page=page)
            page_matches = res.get("matches", []) or []
            for m in page_matches:
                print_match_from_search(m, args, unique_ips, port_to_ips)
            shown += len(page_matches)
            print("-" * 80)
            print(f"[Página {page}] Resultados: {len(page_matches)}")
            print("-" * 80)
            page += 1

    except APIError as e:
        msg = str(e)
        print(f"Error al consultar Shodan (search): {msg}")
        if "403" in msg or "Access denied" in msg:
            print("Tu cuenta no tiene búsquedas habilitadas o no tienes créditos (query_credits=0).")
            print("Sugerencia: usa --mode host --ip-file targets.txt para ejecutar el fallback.")
        return 2

    summary_block(unique_ips, port_to_ips, args)
    return 0


def run_host(api: Shodan, args) -> int:
    if not args.ip_file or not os.path.exists(args.ip_file):
        print("Debes indicar --ip-file con IPs (una por línea) para modo host.")
        return 2

    with open(args.ip_file, "r", encoding="utf-8") as f:
        ips = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]

    if not ips:
        print("El archivo de IPs está vacío.")
        return 2

    print_header(args, f"Modo HOST (fallback) | Archivo: {args.ip_file} | Filtrar GT: {args.gt_only}")

    unique_ips = set()
    port_to_ips = defaultdict(set)

    for ip in ips:
        try:
            host = api.host(ip)
        except APIError as e:
            print("-" * 80)
            print(f"IP        : {ip}")
            print(f"Error     : {e}")
            continue

        if args.gt_only and host.get("country_code") != "GT":
            continue

        data_list = host.get("data", []) or []
        if not data_list:
            print("-" * 80)
            print(f"IP        : {host.get('ip_str') or ip}")
            print(f"País      : {host.get('country_name')} ({host.get('country_code')})")
            print(f"Org       : {host.get('org')}")
            print(f"Hostnames : {', '.join(host.get('hostnames') or []) or '(sin hostnames)'}")
            continue

        for entry in data_list:
            print_match_from_host(host, entry, args, unique_ips, port_to_ips)

    summary_block(unique_ips, port_to_ips, args)
    return 0


def main():
    load_dotenv()
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        print("No se encontró SHODAN_API_KEY. Configura .env o variable de entorno.")
        sys.exit(1)

    args = parse_args()
    api = Shodan(api_key)

    if args.diagnose:
        diagnose(api, api_key)

    if args.mode == "search":
        code = run_search(api, args)
        # Si falla por 403 y el usuario pasó --ip-file, permite continuar con host:
        if code != 0 and args.ip_file:
            print("\nConmutando a modo HOST (fallback) por falta de créditos de búsqueda...\n")
            code = run_host(api, args)
        sys.exit(code)
    else:
        sys.exit(run_host(api, args))


if __name__ == "__main__":
    main()
