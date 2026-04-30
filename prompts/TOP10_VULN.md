# OWASP Top 10 for LLM Applications 2025

This document extracts the top 10 LLM vulnerabilities as requested, focusing strictly on four factors: Description, Common Examples of Vulnerability/Risks, Prevention and Mitigation Strategies, and Example Attack Scenarios.

---

## LLM01:2025 Prompt Injection

### 1. Description
A Prompt Injection Vulnerability occurs when user prompts alter the LLM's behavior or output in unintended ways. These inputs can affect the model even if they are imperceptible to humans. It exists in how models process prompts, forcing the model to violate guidelines, generate harmful content, enable unauthorized access, or influence critical decisions. Jailbreaking is a related concept where the attacker completely overrides safety protocols.

### 2. Types of Prompt Injection Vulnerabilities
* **Direct Prompt Injections:** User's prompt input directly alters the behavior of the model in unintended ways (intentional or unintentional).
* **Indirect Prompt Injections:** The LLM accepts input from external sources (websites, files) containing hidden malicious data that alters behavior.

### 3. Prevention and Mitigation Strategies
1.  **Constrain model behavior:** Provide specific role limitations in the system prompt.
2.  **Define and validate expected output formats:** Specify clear formats and use deterministic code to validate adherence.
3.  **Implement input and output filtering:** Define sensitive categories, apply semantic filters, and evaluate responses (RAG Triad).
4.  **Enforce privilege control and least privilege access:** Provide the app with its own API tokens and restrict access.
5.  **Require human approval for high-risk actions:** Use human-in-the-loop controls for privileged operations.
6.  **Segregate and identify external content:** Separate untrusted content to limit its influence.
7.  **Conduct adversarial testing and attack simulations:** Regular pen-testing treating the model as untrusted.

### 4. Example Attack Scenarios
* **Scenario #1 (Direct):** Attacker instructs customer support chatbot to ignore guidelines and query private data.
* **Scenario #2 (Indirect):** User summarizes a webpage with hidden instructions causing data exfiltration.
* **Scenario #3 (Unintentional):** Applicant optimizes resume, triggering a company's AI detection instruction.
* **Scenario #4 (Intentional Model Influence):** Attacker modifies document in a repository used by a RAG application.
* **Scenario #5 (Code Injection):** Attacker exploits vulnerability in email assistant to inject prompts.
* **Scenario #6 (Payload Splitting):** Malicious prompts are split across a resume to evade detection but combine during evaluation.
* **Scenario #7 (Multimodal):** Malicious prompt embedded within an image accompanying benign text.
* **Scenario #8 (Adversarial Suffix):** Meaningless string appended to prompt bypassing safety measures.
* **Scenario #9 (Multilingual/Obfuscated):** Encoded instructions (Base64, emojis) to evade filters.

---

## LLM02:2025 Sensitive Information Disclosure

### 1. Description
Sensitive information can affect both the LLM and its application context, including PII, financial details, health records, or proprietary models' training methods and source code. This results in unauthorized data access, privacy violations, and intellectual property breaches. Applications should perform data sanitization to prevent user data from entering the training model and apply clear Terms of Use.

### 2. Common Examples of Vulnerability
1.  **PII Leakage:** Personal data disclosed during interactions.
2.  **Proprietary Algorithm Exposure:** Poorly configured outputs reveal algorithms/data, potentially exposing the model to inversion attacks.
3.  **Sensitive Business Data Disclosure:** Generated responses inadvertently include confidential information.

### 3. Prevention and Mitigation Strategies
* **Sanitization:** Integrate data sanitization to scrub content, and apply robust input validation.
* **Access Controls:** Enforce strict access based on least privilege and restrict data sources.
* **Federated Learning and Privacy Techniques:** Utilize federated learning across decentralized data and incorporate differential privacy.
* **User Education and Transparency:** Educate users on safe usage and maintain clear data usage/deletion policies.
* **Secure System Configuration:** Conceal system preamble and reference security misconfiguration best practices.
* **Advanced Techniques:** Use homomorphic encryption and tokenization/redaction.

### 4. Example Attack Scenarios
* **Scenario #1:** Unintentional Data Exposure where a user receives another user's personal data.
* **Scenario #2:** Targeted Prompt Injection bypassing filters to extract sensitive information.
* **Scenario #3:** Data Leak via Training Data where negligent data inclusion leads to disclosure.

---

## LLM03:2025 Supply Chain

### 1. Description
LLM supply chains are susceptible to vulnerabilities affecting the integrity of training data, models, and deployment platforms, leading to biased outputs, security breaches, or system failures. Risks extend beyond traditional code flaws to third-party pre-trained models, datasets, open-access LLMs, "LoRA" fine-tuning methods, and on-device LLMs.

### 2. Common Examples of Risks
1.  Traditional Third-party Package Vulnerabilities.
2.  Licensing Risks (software and dataset restrictions).
3.  Outdated or Deprecated Models.
4.  Vulnerable Pre-Trained Model (hidden biases, backdoors).
5.  Weak Model Provenance (no guarantees on origin).
6.  Vulnerable LoRA adapters.
7.  Exploit Collaborative Development Processes (model merging abuse).
8.  LLM Model on Device supply-chain vulnerabilities.
9.  Unclear T&Cs and Data Privacy Policies.

### 3. Prevention and Mitigation Strategies
1.  Carefully vet data sources and suppliers.
2.  Apply mitigations for vulnerable/outdated components (vulnerability scanning).
3.  Apply comprehensive AI Red Teaming and Evaluations.
4.  Maintain a Software Bill of Materials (SBOM / AI BOM).
5.  Audit AI licensing risks and inventory.
6.  Use verifiable sources and third-party model integrity checks.
7.  Implement strict monitoring for collaborative model environments.
8.  Anomaly detection and adversarial robustness tests.
9.  Implement a strict patching policy.
10. Encrypt edge models with integrity checks.

### 4. Example Attack Scenarios
* **Scenario #1-3:** Vulnerable python library hijacking, direct tampering to spread misinformation, and fine-tuning popular models to bypass benchmarks.
* **Scenario #4-6:** Compromised pre-trained models, vulnerable third-party LoRA adapters, supplier infiltration on device models.
* **Scenario #7-9:** CloudBorne/CloudJacking attacks, Leftovers (GPU local memory leak), fake duplicate models (WizardLM).
* **Scenario #10-13:** Hijacked model merge services, reverse-engineered mobile apps, dataset poisoning for backdoors, privacy policy changes leading to data exposure.

---

## LLM04: Data and Model Poisoning

### 1. Description
Data poisoning occurs when pre-training, fine-tuning, or embedding data is manipulated to introduce vulnerabilities, backdoors, or biases. This is an integrity attack targeting different stages of the LLM lifecycle. It can lead to harmful outputs, impaired capabilities, or create "sleeper agents" whose behavior only changes upon encountering specific triggers.

### 2. Common Examples of Vulnerability
1.  Malicious actors introduce harmful data during training (e.g., Split-View or Frontrunning).
2.  Attackers inject harmful content directly into the training process.
3.  Users unknowingly inject sensitive information exposed in later outputs.
4.  Unverified training data increases bias.
5.  Lack of resource access restrictions allows ingestion of unsafe data.

### 3. Prevention and Mitigation Strategies
1.  Track data origins using tools like CycloneDX or ML-BOM.
2.  Vet data vendors and validate outputs.
3.  Implement strict sandboxing and anomaly detection.
4.  Tailor models using specific datasets for fine-tuning.
5.  Ensure sufficient infrastructure controls.
6.  Use Data Version Control (DVC).
7.  Store user-supplied information in a vector database instead of re-training.
8.  Test robustness with red teaming and federated learning.
9.  Monitor training loss and analyze behavior.
10. Integrate Retrieval-Augmented Generation (RAG) during inference.

### 4. Example Attack Scenarios
* **Scenario #1:** Attacker biases outputs via training data or prompt injection for misinformation.
* **Scenario #2:** Toxic data without filtering propagates dangerous information.
* **Scenario #3:** Falsified documents used for training reflect inaccuracies.
* **Scenario #4:** Inadequate filtering allows misleading data via prompt injection.
* **Scenario #5:** Poisoning techniques insert a backdoor trigger for hidden execution.

---

## LLM05:2025 Improper Output Handling

### 1. Description
Insufficient validation, sanitization, and handling of outputs generated by LLMs before passing them to other components. Because LLM outputs can be controlled by prompts, this acts similarly to indirect access. Exploitation results in XSS, CSRF, SSRF, privilege escalation, or remote code execution.

### 2. Common Examples of Vulnerability
1.  LLM output entered directly into a system shell/eval resulting in RCE.
2.  JS/Markdown generated by the LLM interpreted by the browser (XSS).
3.  LLM-generated SQL executed without parameterization (SQLi).
4.  File paths constructed from LLM output without sanitization (Path Traversal).
5.  LLM content in email templates without escaping (Phishing).

### 3. Prevention and Mitigation Strategies
1.  Treat the model as any other user (zero-trust approach) with input validation on backend functions.
2.  Follow OWASP ASVS guidelines for validation and sanitization.
3.  Encode model output back to users.
4.  Implement context-aware output encoding (HTML, SQL escaping).
5.  Use parameterized queries/prepared statements.
6.  Employ strict Content Security Policies (CSP).
7.  Robust logging and monitoring to detect exploitation patterns.

### 4. Example Attack Scenarios
* **Scenario #1:** Privileged LLM extension receives unvalidated input from a general LLM causing shutdown.
* **Scenario #2:** Website summarizer captures sensitive content via injection and sends to attacker due to zero filtering.
* **Scenario #3:** User requests LLM to craft a SQL query to drop tables, which executes directly.
* **Scenario #4:** Web app renders unsanitized JavaScript payload generated by LLM (XSS).
* **Scenario #5:** LLM generates marketing emails with embedded malicious JS.
* **Scenario #6:** Code generation LLM hallucinates non-existent software packages (malware traps).

---

## LLM06:2025 Excessive Agency

### 1. Description
Vulnerability that enables damaging actions to be performed in response to unexpected, ambiguous, or manipulated outputs from an LLM. It occurs when an LLM agent is granted the ability to autonomously call functions or interface with extensions without proper constraints. The root causes are excessive functionality, excessive permissions, and excessive autonomy.

### 2. Common Examples of Risks
1.  **Excessive Functionality:** Extension contains features not needed (e.g., read/write when only read is needed).
2.  **Excessive Functionality:** Dropped trial extensions remain available to the agent.
3.  **Excessive Functionality:** Open-ended extensions (like shell commands) fail to filter instructions.
4.  **Excessive Permissions:** Connecting to a database with broader privileges than necessary.
5.  **Excessive Permissions:** Operating in the context of a highly-privileged generic identity rather than the individual user.
6.  **Excessive Autonomy:** Failing to independently verify/approve high-impact actions.

### 3. Prevention and Mitigation Strategies
1.  **Minimize extensions:** Only grant minimum necessary extensions.
2.  **Minimize extension functionality:** Strip out unnecessary capabilities within tools.
3.  **Avoid open-ended extensions:** Do not allow arbitrary shell/URL actions; build specific tools.
4.  **Minimize extension permissions:** Restrict the identity database/API permissions.
5.  **Execute in user's context:** Track user authorization and scope.
6.  **Require user approval:** Use human-in-the-loop control before high-impact actions.
7.  **Complete mediation:** Implement authorization in downstream systems, not inside the LLM.
8.  **Sanitise inputs and outputs:** Use ASVS and SAST/DAST pipelines.

### 4. Example Attack Scenarios
* An LLM personal assistant summarizes emails but has an extension that can also *send* emails. An indirect prompt injection in an incoming email commands the agent to read sensitive data and forward it to the attacker. This succeeds because of excessive functionality (ability to send), excessive permissions (broad email scope), and excessive autonomy (no human review before sending).

---

## LLM07:2025 System Prompt Leakage

### 1. Description
The risk that system prompts used to steer the model inadvertently contain sensitive information that was not intended to be discovered. If revealed, this information facilitates other attacks. The core risk is not merely seeing the prompt, but relying on it as a security control or hardcoding secrets, credentials, or internal logic inside it.

### 2. Common Examples of Risk
1.  **Exposure of Sensitive Functionality:** API keys, database credentials, or system architecture hidden in the prompt.
2.  **Exposure of Internal Rules:** Internal decision-making processes (e.g., daily transaction limits) that can be exploited.
3.  **Revealing Filtering Criteria:** Instructions detailing what the model must reject, allowing bypass crafting.
4.  **Disclosure of Permissions and User Roles:** Informing the model of administrative privilege structures, leading to escalation attacks.

### 3. Prevention and Mitigation Strategies
1.  **Separate Sensitive Data:** Avoid embedding secrets or logic rules directly in the system prompt.
2.  **Avoid Reliance for Strict Behavior Control:** Do not use system prompts as the primary boundary for preventing harmful content.
3.  **Implement Guardrails:** Use independent verification systems outside the LLM.
4.  **Enforce Independent Security Controls:** Privilege separation and bounds checks must be handled deterministically outside the LLM.

### 4. Example Attack Scenarios
* **Scenario #1:** A system prompt contains tool credentials. An attacker extracts the prompt and uses the credentials externally.
* **Scenario #2:** An attacker extracts instructions prohibiting offensive content/code execution, then crafts a specific prompt injection to bypass them and facilitate RCE.

---

## LLM08:2025 Vector and Embedding Weaknesses

### 1. Description
Weaknesses in how vectors and embeddings are generated, stored, or retrieved in Retrieval Augmented Generation (RAG) systems. These can be exploited to inject harmful content, manipulate outputs, or access sensitive information when external knowledge sources are augmented.

### 2. Common Examples of Risks
1.  **Unauthorized Access & Data Leakage:** Inadequate access controls to embeddings disclosing sensitive/personal data.
2.  **Cross-Context Information Leaks:** Multi-tenant vector DBs leaking context between users, or knowledge conflicts overriding training data.
3.  **Embedding Inversion Attacks:** Attackers recovering significant amounts of source information by inverting embeddings.
4.  **Data Poisoning Attacks:** Intentional or unintentional poisoned data originating from insiders or unverified sources.
5.  **Behavior Alteration:** RAG inadvertently altering the foundational model's behavioral traits (e.g., losing empathy).

### 3. Prevention and Mitigation Strategies
1.  **Permission and access control:** Implement fine-grained, permission-aware vector stores and strict partitioning.
2.  **Data validation & source authentication:** Audit the knowledge base and accept data only from verified sources.
3.  **Data review for combination & classification:** Tag and classify data when combining sources to prevent mismatch errors.
4.  **Monitoring and Logging:** Maintain immutable logs of retrieval activities.

### 4. Example Attack Scenarios
* **Scenario #1 (Data Poisoning):** Hidden white text on a resume instructs the RAG screening system to highly recommend the candidate.
* **Scenario #2 (Access control risk):** Multi-tenant database inadvertently retrieves embeddings from Group A for Group B's query, leaking business secrets.
* **Scenario #3 (Behavior alteration):** A model loses empathetic response capabilities after being augmented purely with rigid factual financial data.

---

## LLM09:2025 Misinformation

### 1. Description
Misinformation occurs when LLMs produce false or misleading information that appears credible (hallucinations or training bias). This leads to users making decisions based on fabricated information (overreliance), risking security breaches, legal liabilities, and reputational damage.

### 2. Common Examples of Risk
1.  **Factual Inaccuracies:** The model produces incorrect statements leading to real-world disruptions (e.g., airline chatbot errors).
2.  **Unsupported Claims:** Baseless assertions harming sensitive legal or healthcare contexts.
3.  **Misrepresentation of Expertise:** The illusion of understanding complex topics (e.g., misrepresenting medical uncertainty).
4.  **Unsafe Code Generation:** Suggesting insecure or non-existent code libraries containing vulnerabilities.

### 3. Prevention and Mitigation Strategies
1.  **Retrieval-Augmented Generation (RAG):** Enhance outputs with verified external databases.
2.  **Model Fine-Tuning:** Use parameter-efficient tuning and chain-of-thought prompting.
3.  **Cross-Verification and Human Oversight:** Require independent verification and trained reviewers.
4.  **Automatic Validation Mechanisms:** Validate high-stakes outputs programmatically.
5.  **Risk Communication:** Clearly define risks, harms, and reliability limitations to users.
6.  **Secure Coding Practices:** Prevent integration of insecure LLM code suggestions.
7.  **User Interface Design:** Design APIs to label AI content and add content filters.
8.  **Training and Education:** Educate users on the need for critical thinking regarding LLMs.

### 4. Example Attack Scenarios
* **Scenario #1:** Attackers identify non-existent code packages hallucinatory generated by an LLM, publish malware under those names, and compromise developers who run the suggested code.
* **Scenario #2:** A medical chatbot provides inaccurate health information leading to patient harm and a successful lawsuit against the company, with no active attacker involved.

---

## LLM10:2025 Unbounded Consumption

### 1. Description
Occurs when an LLM application allows users to conduct excessive and uncontrolled inferences. The high computational demands make them vulnerable to resource exploitation, leading to Denial of Service (DoS), economic losses (Denial of Wallet), model theft, and service degradation.

### 2. Common Examples of Vulnerability
1.  **Variable-Length Input Flood:** Overloading the LLM with varied inputs to deplete CPU/memory.
2.  **Denial of Wallet (DoW):** High volume of operations exploiting cost-per-use cloud models to cause financial ruin.
3.  **Continuous Input Overflow:** Submitting inputs exceeding the context window to drain processing power.
4.  **Resource-Intensive Queries:** Demanding complex sequences or language patterns to stall the system.
5.  **Model Extraction via API:** Querying the model to collect sufficient outputs to clone a shadow model.
6.  **Functional Model Replication:** Using target model to generate synthetic training data to replicate functionality.
7.  **Side-Channel Attacks:** Exploiting input filtering techniques to harvest model weights/architecture.

### 3. Prevention and Mitigation Strategies
1.  **Input Validation:** Strict bounds on input size.
2.  **Limit Exposure of Logits:** Restrict logprob/logit_bias API returns.
3.  **Rate Limiting:** Quotas per user/source.
4.  **Resource Allocation Management:** Dynamic monitoring of resources.
5.  **Timeouts and Throttling:** Strict caps on processing times.
6.  **Sandbox Techniques:** Restrict network and internal API access.
7.  **Logging and Anomaly Detection:** Track unusual usage patterns.
8.  **Watermarking:** Detect unauthorized use of LLM outputs.
9.  **Graceful Degradation:** Maintain partial functionality under heavy load.
10. **Limit Queued Actions:** Dynamic scaling to handle demands.
11. **Adversarial Robustness Training:** Train models to detect extraction attempts.
12. **Glitch Token Filtering:** Scan outputs for known glitch tokens.
13. **Access Controls:** RBAC to limit model repository access.
14. **Centralized ML Model Inventory:** Proper governance.
15. **Automated MLOps Deployment:** Tight deployment controls.

### 4. Example Attack Scenarios
* **Scenario #1:** Extremely large input crashes text-processing LLM (Memory/CPU overload).
* **Scenario #2:** API flooded with requests making service unavailable.
* **Scenario #3:** Input crafted to trigger computationally expensive processes.
* **Scenario #4:** Attacker exploits pay-per-use model creating massive cloud billing (DoW).
* **Scenario #5:** Attacker fine-tunes a shadow model using synthetic data generated from the target API.
* **Scenario #6:** Side-channel attack retrieves model information to a remote server by bypassing preambles.
