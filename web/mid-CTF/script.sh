URL="http://141.85.224.118:8084/"
CHARACTERS= $1

for ((i=0; i<${#CHARACTERS}; i++)); do
    curl -s -X GET "${URL}${CHARACTER}"
done
