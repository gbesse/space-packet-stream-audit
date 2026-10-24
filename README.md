# space-packet-stream-audit

## Français

Où le flux binaire de télémétrie devient-il incomplet ou ambigu ?.

Données fictives ; aucun accès réseau ni secret requis.

```sh
python -m space_packet_stream_audit examples/demo.json --lang fr
python -m unittest discover -s tests -v
```

### Méthode et différence

Lit les vrais six octets den-tête CCSDS et la longueur moins un, puis produit offsets et ambiguïtés modulo 16384 par APID. F Prime et CCSDSPack existent déjà ; cet outil est un témoin négatif portable, distinct du rejeu daccusés packet-custody-replay.

### Limites

Pas de décodage secondaire, CRC, synchronisation de trame ou certification CCSDS. Un saut de compteur nest une perte que sous hypothèses explicites sans reset ni grand réordonnancement.

### Validation

Tests de domaine, cas limites et interface FR/EN/ES. La CI teste Python 3.11/3.13 et exécute la wheel installée hors du checkout. JSON conserve les identifiants techniques et les données fournis. Erreur d’entrée : code de sortie 2.

## English

Where does a binary telemetry stream become incomplete or ambiguous?.

Synthetic data; no network access or secret required.

```sh
python -m space_packet_stream_audit examples/demo.json --lang en
python -m unittest discover -s tests -v
```

### Method and difference

Reads actual six-byte CCSDS headers and length-minus-one, then reports offsets and per-APID modulo16384 ambiguities. F Prime and CCSDSPack already exist; this is a portable negative witness, distinct from packet-custody-replay acknowledgements.

### Limits

No secondary decoding, CRC, transfer-frame synchronization or CCSDS certification. A counter jump indicates loss only under explicit no-reset/no-large-reordering assumptions.

### Validation

Domain tests, boundary cases and FR/EN/ES interface. CI tests Python 3.11/3.13 and runs the installed wheel outside the checkout. JSON preserves technical identifiers and supplied data. Invalid input exits with code 2.

## Español

¿Dónde se vuelve incompleto o ambiguo un flujo binario de telemetría?.

Datos sintéticos; no requiere red ni secretos.

```sh
python -m space_packet_stream_audit examples/demo.json --lang es
python -m unittest discover -s tests -v
```

### Método y diferencia

Lee cabeceras CCSDS reales de seis bytes y longitud menos uno; informa desplazamientos y ambigüedades módulo16384 por APID. F Prime y CCSDSPack ya existen; es un testigo negativo portátil, distinto de los acuses de packet-custody-replay.

### Límites

Sin decodificación secundaria, CRC, sincronización de tramas ni certificación CCSDS. Un salto solo indica pérdida bajo hipótesis explícitas sin reinicio ni gran reordenación.

### Validación

Pruebas de dominio, casos límite e interfaz FR/EN/ES. CI prueba Python 3.11/3.13 y ejecuta la wheel instalada fuera del repositorio. JSON conserva identificadores técnicos y datos proporcionados. Entrada inválida termina con código 2.

## Sources / Fuentes

- https://ccsds.org/Pubs/133x0b2e2.pdf
- https://fprime.jpl.nasa.gov/devel/docs/reference/system-functional/ccsds-protocol/
