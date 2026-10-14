# 🥗 Sistema de Assessoria Nutricional Esportiva

**Universidade Estadual de Ciências da Saúde de Alagoas (UNCISAL)**  
**Pós-Graduação em Segurança da Informação**  
**Disciplina:** Projeto Aplicado: Práticas de Mercado  

---

## 📌 1. Visão Geral

Este sistema de **Assessoria Nutricional Esportiva** foi desenvolvido exclusivamente para nutricionistas. O seu principal objetivo é atuar como uma ferramenta segura de suporte à decisão clínica, automatizando a leitura de dados de Bioimpedância Segmental (balanças Tanita de 8 eletrodos) e auxiliando o profissional na elaboração, validação e ratificação de dietas personalizadas de forma ágil, precisa e segura.

---

## ⚙️ 2. Arquitetura e Engenharia de Software

A aplicação foi desenvolvida em **Python + Flask**, desenhada para alta performance e resiliência a falhas:
* **Integração Groq Cloud com LLMs:** Processamento inteligente utilizando modelos como `qwen3.8-27b`, `gpt-oss-20b` e `llama-3.3-70b-versatile` para estruturar o rascunho do planeamento alimentar com base nos parâmetros clínicos fornecidos.
* **Processamento Híbrido de CSV:** Leitura robusta que trata inconsistências de exportação em arquivos gerados por diferentes balanças.
* **Geração de Laudos e PDF:** Conversão de Markdown para HTML, criando relatórios clínicos formatados, prontos para a revisão do nutricionista e posterior impressão.

---

## 🛡️ 3. Segurança da Informação (OWASP Top 10:2025)

Como requisito central da Pós-Graduação em Segurança da Informação, o software incorpora rigorosas práticas de *Defense in Depth* alinhadas à taxonomia oficial do **OWASP Top 10:2025**, mitigando ativamente as seguintes vulnerabilidades:

### OWASP A07:2025 - Authentication Failures (Quebra de Autenticação e Timing Attacks)
* **Rate Limiting em Memória:** Bloqueio automático de IP (status HTTP `429 Too Many Requests`) após 4 tentativas de login falhadas numa janela de 300 segundos, travando ataques de Força Bruta.
* **Mitigação de Timing Attacks:** Comparação das credenciais de acesso realizada em tempo constante através da função `hmac.compare_digest()`.
* **Prevenção de Session Fixation:** Execução de `session.clear()` no momento do login bem-sucedido, garantindo a renovação completa da sessão ativa.

### OWASP A01:2025 - Broken Access Control & Anti-IP Spoofing
* **Proteção de Proxy Reverso:** Utilização do middleware `ProxyFix` para inibir a falsificação de cabeçalhos `X-Forwarded-For` e tentativas de mascaramento de IP por agentes maliciosos.
* **Controle de Acesso Restrito:** Todas as rotas sensíveis e de gestão de ficheiros estão rigidamente protegidas pelo decorator `@login_required`. Acessos não autenticados são barrados na origem.

### OWASP A05:2025 / A06:2025 - Injection (Stored XSS) e Insecure Design
* **Limitação de Payload (DoS):** Uploads estritamente restritos a 2MB no nível do servidor para evitar sobrecarga.
* **Validação de Ficheiros:** O sistema aceita exclusivamente ficheiros com a extensão `.csv`.
* **Anti-Path Traversal e Colisão:** Renomeação automática e criptográfica de ficheiros via `uuid4().hex` e `secure_filename()`, impossibilitando ataques de injeção de diretório.
* **Sanitização de XSS:** Uso obrigatório de `html.escape()` em todas as células de dados extraídas antes de qualquer renderização visual, neutralizando injeções de scripts no navegador.

---

## 🧪 4. Utilização do Sistema

1. Abra o navegador e aceda à página de login segura.
2. Efetue a autenticação com as credenciais protegidas do nutricionista.
3. No painel clínico, faça o upload do ficheiro CSV da avaliação de bioimpedância.
4. Selecione a estratégia calórica planeada, o nível de atividade física do paciente e eventuais restrições clínicas.
5. Clique em **"Processar Bioimpedância & Gerar Plano com IA"** para obter o laudo metabólico e a sugestão estruturada do plano alimentar, que ficará pronta para a análise, validação e ratificação do profissional responsável.