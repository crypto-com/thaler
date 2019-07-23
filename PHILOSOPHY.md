# Design Goals
On the technical side, the vision described in whitepapers etc. translates into the following goals:

1. "Security": robust and well-understood primitives and implementation are favoured

2. "Scalability": parts that hinder overall latency, throughput, lightweight client support, etc. should be mitigated

3. "Multi-party": the system should permit multi-party operation; anything that puts trust in a single party should be opt-in

4. "Long-term operation": there needs to be a leeway for backwards- and forwards-compatibility etc.

5. "Privacy": value transfer transactions need to have a level of confidentiality, while providing a way for external accountability

6. "Developer ecosystem": external developers can easily work with Chain, regardless of their used programming language

## Initial Design Philosophy

1. Non-strict adherence to [Boring Software Manifesto](https://tqdev.com/2018-the-boring-software-manifesto):

- While "blockchain" is surely a trendy buzzword, we initially chose Tendermint which is a fairly "boring" PBFT-like consensus.

- Any exceptions should be with a reason and ideally backed by data:

* For example, Rust is a fairly new systems programming language. At the same time, [Project Zero data](https://googleprojectzero.blogspot.com/p/0day.html) identified that memory corruption issues (that Rust would prevent) were the root-cause of 68% of listed CVEs.

2. Simplicity over flexibility:

- For example, we don't aim to support general recursive smart contracts. Instead, we would try to push the existing digital signatures in different ways (e.g. "scriptless scripts").

3. Efficient resource use:

- small transaction sizes

- cheap / fast transaction validation

- use blockchain only where Byzantine fault-tolerant robustness is needed

4. Opt-in single third-party trust:

- For example, there's a service that improves UX, but relies on a single party providing that service. This is acceptable, but it has to be strictly opt-in and the core functionality should still work without the third party.

5. Room for multi-party operation:

- While the initial distribution and operation gravitates towards Crypto.com, 
the core technology should not prevent the continual shift in ownership, responsibilities etc.