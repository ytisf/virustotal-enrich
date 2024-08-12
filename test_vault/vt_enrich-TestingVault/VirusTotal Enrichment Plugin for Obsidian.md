## About
The VirusTotal Enrichment Plugin for Obsidian allows you to enhance your notes by querying VirusTotal directly within Obsidian. You can enrich notes with detailed properties of files, URLs, IP addresses, or domains, which can then be utilized within the note's body or as metadata for advanced querying capabilities, particularly with plugins like [dataview](https://blacksmithgu.github.io/obsidian-dataview/).

## How to Use
To use the VirusTotal Enrichment Plugin, follow these steps:
1. Install the plugin via Obsidian’s third-party plugin settings.
2. Obtain an API key from [VirusTotal](https://www.virustotal.com/gui/join-us).
3. Enter your API key in the plugin settings within Obsidian.
4. Use the command palette (`Ctrl/Cmd + P`) to run VirusTotal queries:
   - `Enrich Current Note`: Enriches the open note with data fetched from VirusTotal based on content detected in the note.

## How to - Settings
Navigate to the plugin settings in Obsidian to configure the following options:
- **API Key**: Securely store your VirusTotal API key.
- **Include Page Type**: Toggle to include the type of page (e.g., indicator, IP, URL) as a note property.
- **Custom Fields**: Define which properties from VirusTotal you wish to include in your notes, such as `md5`, `sha256`, `filetype`, etc.

## How to - Dataview Examples
Once your notes are enriched, you can utilize Dataview to create dynamic lists and tables based on the enriched data. Here are a few example queries:
````
```dataview
table md5, sha256, creation_date
from "notes-folder"
where contains(filetype, "executable")
```
````

````
```dataview
list
from "notes-folder"
where sha256 = "specific-hash-value"
```
````

See more examples in this repo in [this link](https://github.com/ytisf/virustotal-enrich/dataview_examples.md). 

## License
This project is licensed under the GNU License - see the LICENSE file for details.

## Thanks
Special thanks to:
- The developers of [Obsidian](https://github.com/obsidianmd) for creating such a versatile tool.
- The [VirusTotal](https://github.com/VirusTotal/vt-py) team for providing the API.
- Thanks to a good friend (namesless for now) who provided the push i needed to tackle NodeJS and overcome my laziness for a plugin i was hoping someone else would develop...

## How to Contribute
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

### Fork the Project
- Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
- Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
- Push to the Branch (`git push origin feature/AmazingFeature`)
- Open a Pull Request

For more detailed instructions, you may follow the standard GitHub documentation on creating a pull request.