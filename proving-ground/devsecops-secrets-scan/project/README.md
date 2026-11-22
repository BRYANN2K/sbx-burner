# billing-exporter

Reads a usage CSV (`account,units` columns) and prints a per-account JSON
summary. No dependencies beyond Python 3.

```sh
python3 exporter.py usage.csv
```
