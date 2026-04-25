# Wolf Solutions

Security research tools and payloads from [wolf-solutions.dev](https://wolf-solutions.dev).

## Structure

```
tools/          Security tooling
  sentinel/     LLM log classifier and prompt injection test harness
payloads/       Reusable attack payloads for testing
  prompt-injection/   Log-based prompt injection payloads
research/       Reproduction methodology and notes
```

## Tools

### Sentinel

Feeds SIEM log events to a security-focused LLM and tests whether prompt injection hidden in log fields can manipulate the model's classification. Supports Ollama, MLX, and Anthropic backends.

See [tools/sentinel/](tools/sentinel/) for usage.

Blog post: [The Smarter the Model, the Easier to Fool](https://wolf-solutions.dev/whoami/stdout/smarter-model-easier-to-fool/)

## License

MIT
