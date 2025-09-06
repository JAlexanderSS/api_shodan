# Shodan Guatemala CLI

Script de consola para consultas a Shodan enfocadas en Guatemala.

## Modos

1. SEARCH (cumple consigna)

   - Requiere cuenta con `query_credits > 0` y acceso a `api.search`.
   - Usa filtro del alumno + `country:"GT"`, prohíbe `org:`.

2. HOST (fallback)
   - Para cuentas sin créditos: consulta IPs desde archivo con `api.host(IP)`.
   - Genera el mismo resumen (IPs únicas e IPs por puerto).
   - **No reemplaza** el filtro por ciudad de la consigna.

## Instalación

```bash
pip install -r requirements.txt
```

## Sin creditos usamos esto para ejecutar el script

```
python shodan_gt_scan.py --mode host --ip-file targets.txt --carne 1990-21-2784 --nombre "José Alexander Sey Sirin" --curso "Seguridad y Auditoría de Sistemas" --seccion "A"
```

## Con creditos usamos este comando para ejecutar el script
```
python shodan_gt_scan.py --mode search --filter 'city:"Jalapa" port:3389' --carne 202312345 --nombre "José Alexander Sey Sirin" --curso "Seguridad Ofensiva" --seccion "A" --max-pages 1
```