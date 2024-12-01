#!/bin/bash

# Reemplaza con la ruta correcta al archivo 'commands'
archivo="commands"

# Verifica si el archivo existe
if [ ! -f "$archivo" ]; then
  echo "El archivo $archivo no existe."
  exit 1
fi

# Leer el archivo línea por línea y ejecutar el comando rpcclient
while IFS= read -r comando; do
  echo "$comando"
  rpcclient -U "" 192.168.136.152 -N -c "$comando"
  echo -ne "\n"
done < "$archivo"
