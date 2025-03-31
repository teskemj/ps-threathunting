# ps-threathunting

``` mermaid
flowchart LR
    A([Attacker]) --> B{Reconnaissance<br/>(Identify Next.js app)}
    B --> C{Check/Reveals<br/>Rewrite Rules & basePath}
    C --> D(Craft Malicious Request<br/>to Exploit Rewrites)
    D --> E{Server Processes<br/>Rewrite Incorrectly}
    E --> F{Unauthorized Access<br/>to Internal Files/Endpoints}
    F --> G(Exfiltrate Data /<br/>Further Pivot)
```
