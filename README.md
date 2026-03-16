# tmautils-enrich-ip
IP enrichment utilities for Internet measurement research. Part of the [tmautils](https://github.com/sulyabtv/tmautils) package family.

Installation:
```bash
pip install tmautils-enrich-ip
```

## API

| Utility / Function | What it does |
| --- | --- |
| `IPApiBatchUtil` | Interact with `ip-api.com`'s batch API |
| `IPInfoLiteUtil` | Interact with the IPinfo's Lite dataset |
| `IpInfoPrivacyUtil` | Privacy detection using IPinfo's database |
| `IpInfoCarrierUtil` | Mobile carrier lookup using IPinfo's database |
| `ChromePrefetchUtil` | Check if an IP address belongs to Chrome Prefetch Proxy |

## License
This project is licensed under [MPL-2.0](LICENSE) (Mozilla Public License 2.0).

What this means in practice:
- If you modify an existing file, your modifications must remain MPL-2.0.
- You can license new files however you want. (But I won't merge them unless they are MPL-2.0.)
- You can use this code alongside code under other licenses.

## Contributing
Contributions are highly welcome! See the [tmautils README](https://github.com/sulyabtv/tmautils/blob/main/README.md) for philosophy and design choices.

AI Policy: I don't consider AI tool usage any different from IDE usage. This also means that *you* are responsible for the code you write and *you* should inspect every line of code written by an LLM.
