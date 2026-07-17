# devaipod

This project was a useful experiment, however the author has found it easier in practice to
just use separate isolated Unix users or other tools, and now investing in [OpenShell](https://github.com/NVIDIA/OpenShell)
among other things.

Historical README.md content:

---

A fine-grained sandboxing tool for agentic AI that can run 100% locally. No "open core" here, no cloud services except those you configure.

Combines in an opinionated way:

- [OpenCode](https://github.com/anomalyco/opencode/) as agent framework
- [Podman](https://github.com/containers/podman/) as container isolation
- [Devcontainers](https://containers.dev/) as a specification mechanism
- [service-gator](https://github.com/cgwalters/service-gator) as fine-grained MCP server for Github/Gitlab/Forgejo/etc

To be clear: this tool is primarily designed by @cgwalters who would "un-invent" large language models if he could because he believes the long term negatives for society are likely to outweigh the gains. But since that's not possible, this project is about maximizing the positive aspects of LLMs with a focus on software production. We need to use LLMs safely and responsibly, with efficient human-in-the-loop controls and auditability.

However, @cgwalters uses LLMs every day. If you use LLMs or want to, but have heard of e.g. [prompt injection](https://simonwillison.net/tags/prompt-injection/) attacks and share similar concerns from un-sandboxed agent use, then devaipod can help you, as it does the author.

## Documentation

Full documentation including quick start is available at **[cgwalters.github.io/devaipod](https://cgwalters.github.io/devaipod)**

## Related Projects

See the [full comparison](https://cgwalters.github.io/devaipod/related-projects.html) in the docs. Key projects in this space include [OpenHands](https://github.com/All-Hands-AI/OpenHands), [SWE-agent](https://github.com/princeton-nlp/SWE-agent), [Ambient Code](https://github.com/ambient-code/platform), [Scion](https://github.com/GoogleCloudPlatform/scion), [Auto-Claude](https://github.com/AndyMik90/Auto-Claude), [Continue](https://github.com/continuedev/continue), and [Goose](https://github.com/block/goose).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for contribution guidelines.

## License

Apache-2.0 OR MIT
