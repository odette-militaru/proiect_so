#!/bin/bash

file_path="$1"
izolated_dir="$2"

# Asigurați-vă că fișierul există
if [ ! -f "$file_path" ]; then
    echo "The file does not exist: $file_path"
    exit 1
fi

line_count=$(wc -l < "$file_path")
word_count=$(wc -w < "$file_path")
char_count=$(wc -m < "$file_path")

# Debugging output pentru a verifica valorile
echo "Lines: $line_count, Words: $word_count, Characters: $char_count"

# Utilizați 'grep -a' pentru a trata fișierele binare ca text
if grep -a -qiE 'corrupted|dangerous|risk|attack|malware|malicious' "$file_path" || LC_ALL=C grep -a -qP '[^\x00-\x7F]' "$file_path"; then
    malicious_content_found=1
else
    malicious_content_found=0
fi

# Debugging output pentru a verifica detecția
if [ "$malicious_content_found" -eq 1 ]; then
    echo "Malicious content found."
else
    echo "No malicious content found."
fi

# Verificarea condițiilor pentru a determina dacă fișierul este suspect
if [ "$malicious_content_found" -eq 1 ]; then
    echo "periculos"
    mv "$file_path" "$izolated_dir" # Izolarea fișierului
else
    echo "SAFE"
fi
