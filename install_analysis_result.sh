#!/bin/bash

echo "[INFO] Unzipping analysis_result.zip"

if [ -d "analysis" ]; then
  echo "[INFO] 'analysis' folder exists! Nothing to do."
  exit 0
fi

# add link to Nico's server
# wget https://drive.google.com/file/d/1enJJL0dlBxs9T5TzpajOUa6XpFckaccW/view?usp=sharing

unzip analysis_result.zip 
