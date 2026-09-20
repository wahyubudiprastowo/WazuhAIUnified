# Wazuh Indexer ISM helper

`manage-ism.sh` membantu menangani **akumulasi data** di sisi *storage* indexer
(menambahkan retensi), tanpa mengubah fitur lain dan **tanpa restart** Wazuh.

> Satu node (`discovery.type: single-node`) tidak dapat melakukan **tiering fisik
> hot/warm/cold** — itu butuh node yang berperan khusus. Di sini "tiering" praktis
> = **ISM retention policy**: membatasi umur index `wazuh-alerts-*` sehingga data
> lama = dihapus otomatis oleh ISM setelah umur tercapai.
>
> **Kebijakan tim (`mcp-dashboard/RETENTION.md`):** log deletion TIDAK diaktifkan
> otomatis. Alat ini sengaja bersifat *read-only* secara default dan melindungi
> dengan guard `--confirm`. `apply-policy` hanya menyasar **indeks masa depan
> `wazuh-alerts-*`** dan **tidak menyentuh** index state/security/system.

## Cara pakai (amankan, bertahap)

1. **Inventory** (read-only, ukur pertumbuhan & policy yang sudah ada):
   ```bash
   export WAZUH_INDEXER_URL=https://localhost:9200
   export WAZUH_INDEXER_USER=admin
   export WAZUH_INDEXER_PASSWORD=<secret>
   ./manage-ism.sh inventory
   ```
2. **Lihat policy ISM yang ada** (read-only):
   ```bash
   ./manage-ism.sh list-policies
   ```
3. **Simulasi** (tanpa mengubah apa pun):
   ```bash
   ./manage-ism.sh dry-run --retention-days 90
   ```
4. **Terapkan** hanya setelah backup & review retensi (butuh flag eksplisit):
   ```bash
   ./manage-ism.sh apply-policy --retention-days 90 --confirm
   ```
   Ini membuat policy `wazuh-alerts-retention` + template yang menempelkannya ke
   **indeks masa depan `wazuh-alerts-*`**. Indeks yang sudah ada tidak disentuh;
   untuk itu ada langkah manual tambahan yang dicetak oleh script.

## File
- `manage-ism.sh` — script utama (bash, tanpa dependensi eksternal selain `curl`).
- `wazuh-alerts-ism-policy.json` — template policy retensi (90 hari), dimodifikasi
  saat runtime melalui `--retention-days`.