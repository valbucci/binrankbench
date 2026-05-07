#!/usr/bin/env bash

raw_data_dir="/home/valbux/Documents/Life/QUB/MySoftware/binrankbench/data/marcelliMissing/zlib"
output_dir="/home/valbux/Documents/Life/QUB/MySoftware/binrankbench/data/marcelliMissingGrouped/zlib"
mkdir -p $output_dir
n_cfgs_total="$(find "$raw_data_dir" -mindepth 1 -maxdepth 1 -type d -name "*_func-cfg" -printf x | wc -c)"
n_cfgs_done=0

echo "## Processing CFGs ($n_cfgs_total) ..."

find "$raw_data_dir" -mindepth 1 -maxdepth 1 \
  -type d -name "*_func-cfg" -print0 | LC_ALL=C sort -z |
  while IFS= read -r -d '' cfg_dir; do
    output_path="${output_dir}/$(basename "$cfg_dir").jsonl"
    # If the file already exists skip it
    if [[ -s "$output_path" ]]; then
      ((++n_cfgs_done))
      echo "[${n_cfgs_done}/${n_cfgs_total}] Skipping $output_path"
      continue
    fi
    tmp_out_path="${output_path}.tmp"
    find "$cfg_dir" -maxdepth 1 -type f -name "*.json" -print0 |
      LC_ALL=C sort -z |
      xargs -0 -r -n 1000 jq -c . -- >"$tmp_out_path"
    mv -f -- "$tmp_out_path" "$output_path"

    ((++n_cfgs_done))
    echo "[$n_cfgs_done/$n_cfgs_total] Done ${output_path}"
  done
