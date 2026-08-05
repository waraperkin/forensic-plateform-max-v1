# Velociraptor — configuration locale

Les fichiers `server.config.yaml` et `api.config.yaml` **ne sont pas versionnés**
(ils contiennent des clés privées).

## Génération

```bash
# Depuis la racine du dépôt
PUBLIC_HOST=<ip-ou-hostname> FP_VR_NGINX_ONLY=1 bash velociraptor/scripts/generate-config.sh

# Puis sidecar (+ api.config après premier boot)
bash scripts/ensure-velociraptor-sidecar.sh
# ou setup master (génère aussi api.config.yaml)
bash scripts/helk_velociraptor_master_setup.sh
```

Ces étapes sont aussi couvertes par `./forensic.sh deploy portals-forensic` /
`./forensic.sh -full-start` via `setup-sidecars.sh`.
