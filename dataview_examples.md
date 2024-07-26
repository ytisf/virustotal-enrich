
# Dataview Examples for VirusTotal Enrichment Plugin

The following examples demonstrate how you can use the Dataview plugin to leverage the data enriched via the VirusTotal Enrichment Plugin in Obsidian.

## Example 1: List All Executables
Generate a list of all notes containing executable files with their MD5 and SHA256 hashes.

\`\`\`dataview
table md5, sha256, creation_date
from "notes-folder"
where filetype = "executable"
\`\`\`

## Example 2: Find Specific Hash
Display notes where the SHA256 hash matches a specific value. Useful for tracking specific threats.

\`\`\`dataview
list
from "notes-folder"
where sha256 = "specific-hash-value"
\`\`\`

## Example 3: Group By File Type
Group notes by file type and list their corresponding hashes.

\`\`\`dataview
table filetype, md5, sha256
from "notes-folder"
group by filetype
\`\`\`

## Example 4: Recent Submissions
List recent submissions by creation date.

\`\`\`dataview
list creation_date, name
from "notes-folder"
sort creation_date desc
\`\`\`

## Example 5: Large Files
Identify large files in your notes, which could be potential high-risk items.

\`\`\`dataview
table name, size, md5
from "notes-folder"
where size > 1000000
sort size desc
\`\`\`

These examples provide a starting point for querying and organizing your enriched data effectively.
