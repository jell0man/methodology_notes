~/tools/
Username Anarchy generates potential usernames based on a target's name

| Command                               | Description                                                                                   |
| ------------------------------------- | --------------------------------------------------------------------------------------------- |
| `username-anarchy Jane Smith`         | Generate possible usernames for "Jane Smith"                                                  |
| `username-anarchy -i names.txt`       | Use a file (`names.txt`) with names for input. Can handle space, CSV, or TAB delimited names. |
| `username-anarchy -a --country us`    | Automatically generate usernames using common names from the US dataset.                      |
| `username-anarchy -l`                 | List available username format plugins.                                                       |
| `username-anarchy -f format1,format2` | Use specific format plugins for username generation (comma-separated).                        |
| `username-anarchy -@ example.com`     | Append `@example.com` as a suffix to each username.                                           |
| `username-anarchy --case-insensitive` | Generate usernames in case-insensitive (lowercase) format.                                    |

