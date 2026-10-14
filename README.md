# 🥗 Sistema de Assessoria Nutricional Inteligente (Tanita 8 Eletrodos)

**Universidade Estadual de Ciências da Saúde de Alagoas (UNCISAL)**  
**Pós-Graduação em Segurança da Informação**  
**Disciplina:** Projeto Aplicado: Práticas de Mercado  
**Autora:** Silvia Millena Rocha Torres  

---

## 📌 1. Eixo 1: Fundamentação e Domínio do Negócio

O sistema foi concebido para digitalizar e potencializar a tomada de decisão clínica do nutricionista esportivo e clínico a partir da avaliação de **Bioimpedância Segmental por 8 Eletrodos (Balança Tanita)**.

Diferente de balanças bipolares convencionais (que medem apenas membros inferiores ou superiores por estimativa de circuito fechado), o sistema com **8 eletrodos** utiliza correntes elétricas de dupla frequência distribuídas entre mãos (duas manoplas) e pés (duas plataformas condutivas). Isso viabiliza a avaliação segmental precisa dos seguintes compartimentos:
* Braço Esquerdo e Braço Direito;
* Perna Esquerda e Perna Direita;
* Tronco corporal (região torácica e abdominal).

### Automação Fisiológica do Bloco 8
Ao realizar o upload do arquivo CSV com as 33 colunas exportadas pela balança, a aplicação executa automaticamente em Python os cálculos fisiológicos do **Bloco 8**:
1. **Massa Gorda Total (kg):** $\text{Peso} \times \left(\frac{\%\text{Gordura}}{100}\right)$
2. **Massa Livre de Gordura - MLG (kg):** $\text{Peso} - \text{Massa Gorda}$
3. **Taxa Metabólica Basal (Equação de Katch-McArdle):**  
   $$\text{TMB}_{\text{Katch}} = 370 + (21.6 \times \text{Massa Muscular Total (kg)})$$  
   Permite correlacionar a TMB calculada com a TMB estimada pelo algoritmo proprietário da Tanita.
4. **Média de Adiposidade dos Membros Periféricos:**  
   $$\text{Média Membros} = \frac{\% \text{Gordura BE} + \% \text{Gordura BD} + \% \text{Gordura PE} + \% \text{Gordura PD}}{4}$$
5. **Alerta de Dispersão Segmental no Tronco:**  
   Se $(\% \text{Gordura Tronco} - \text{Média Membros}) \ge 3.0\%$, o sistema emite parecer de atenção clínica sobre acúmulo adiposo troncular e valida a simetria muscular bilateral.

---

## ⚙️ 2. Eixo 2: Arquitetura Tecnológica e Engenharia de Software

A aplicação foi desenvolvida em **Python + Flask**, priorizando código limpo, alta performance e resiliência a falhas de rede e infraestrutura.

### Destaques da Arquitetura:
* **Conectividade Groq Cloud com Fallback de Modelos:** A integração utiliza a biblioteca `openai` apontando para `base_url="https://api.groq.com/openai/v1"`. Um loop com resiliência (`for modelo_tentativa in modelos_seguros:`) itera sobre os modelos:
  1. `qwen/qwen3.8-27b`
  2. `openai/gpt-oss-20b`
  3. `llama-3.3-70b-versatile`
  Caso o módulo `openai` não esteja disponível no ambiente ou ocorra falha de biblioteca, o código chaveia automaticamente para requisições nativas via `urllib.request`.
* **Leitura Híbrida de CSV (Pandas + Módulo Nativo `csv`):** O leitor trata anomalias comuns de exportação, como o caso em que o software Microsoft Excel envolve linhas inteiras em aspas duplas externas (`"col1,col2,col3"`).
* **Renderização Segura de Markdown:** A resposta estruturada do LLM é convertida para HTML através do módulo `markdown` com a extensão `tables`, permitindo que cardápios, substituições e fases trimestrais sejam impressos com diagramação profissional.
* **Persistência de Sessão e Cache Clínico:** O laudo processado e os cards do Bloco 8 são salvos em `dados_paciente.json`, permitindo ao nutricionista consultar o `/plano_atual` a qualquer instante sem necessidade de reprocessar o CSV.

---

## 🛡️ 3. Eixo 3: Segurança da Informação (OWASP Top 10:2025)

Como requisito central da Pós-Graduação em Segurança da Informação, o software incorpora práticas de *Defense in Depth* alinhadas à taxonomia oficial do **OWASP Top 10:2025**. A seguir detalham-se onde encontrar no código-fonte e como funcionam as 3 mitigações principais:

### 1. OWASP A07:2025 - Authentication Failures (Quebra de Autenticação / Força Bruta & Timing Attacks)
* **Onde encontrar no código:** Arquivo `app.py`, rotas `@app.route('/login')`, `@app.route('/logout')` e decorators `@login_required`.
* **Como foi implementado:**
  1. **Rate Limiting em Memória:** O dicionário `TENTATIVAS_FALHAS` mapeia o IP do cliente e o timestamp da requisição. Se o mesmo IP falhar 4 vezes dentro de uma janela deslizante de 300 segundos (5 minutos), a rota responde imediatamente com status HTTP `429 Too Many Requests`.
  2. **Mitigação de Timing Attacks:** A comparação entre as credenciais enviadas e as variáveis de ambiente (`ADMIN_USER` e `ADMIN_PASSWORD`) é realizada com `hmac.compare_digest()`, eliminando vazamento de tempo de CPU que possibilitaria a enumeração de credenciais.
  3. **Mitigação de Session Fixation:** No momento do login bem-sucedido, o sistema executa `session.clear()` antes de emitir a nova credencial de sessão.

### 2. OWASP A01:2025 - Broken Access Control & Anti-IP Spoofing em Proxy Reverso
* **Onde encontrar no código:** Arquivo `app.py`, configuração `ProxyFix` e decorator `@login_required`.
* **Como foi implementado:**
  1. **Proteção de Proxy Reverso (Nginx / Oracle Cloud):**  
     `app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)`  
     Isso impede que agentes maliciosos forjem cabeçalhos `X-Forwarded-For` para burlar o Rate Limiting e a auditoria de acessos.
  2. **Controle de Acesso Rígido:** Todas as rotas sensíveis (`/`, `/upload`, `/plano_atual`) são protegidas pelo decorator `@login_required`, redirecionando qualquer acesso não autenticado para `/login`.

### 3. OWASP A05:2025 - Injection (Stored XSS) e OWASP A06:2025 - Insecure Design (Uploads de Arquivo)
* **Onde encontrar no código:** Arquivo `app.py`, configurações `MAX_CONTENT_LENGTH`, `@app.errorhandler(413)`, função `upload_file()` e geração de tabela.
* **Como foi implementado:**
  1. **Mitigação de Negação de Serviço (DoS):** O upload é restrito no nível do servidor a 2MB (`app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024`), sendo tratado de forma elegante pelo interceptador `@app.errorhandler(413)` com mensagem amigável via `flash`.
  2. **Validação de Extensão:** Apenas a extensão `.csv` é aceita (`ALLOWED_EXTENSIONS = {'csv'}`).
  3. **Neutralização de Path Traversal e Colisão:** O nome do arquivo no disco é composto por `f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"`, impossibilitando a sobrescrita de arquivos e ataques de injeção de diretório (`../`).
  4. **Sanitização contra XSS:** Todas as células e cabeçalhos lidos do CSV passam obrigatoriamente por `html.escape()` antes da injeção no template HTML (`tabela_html`), neutralizando tentativas de Stored Cross-Site Scripting.

> 🔒 **Nota de Conformidade LGPD e Privacidade de Dados Clínicos:** Em respeito às práticas de *Privacy by Design* e proteção de dados sensíveis de saúde (Eixo 2), todos os arquivos de dados de bioimpedância (`*.csv`) estão estritamente bloqueados no `.gitignore` para evitar exposição em repositório público. O arquivo de homologação (`bioimpedancia_tanita_joao_do_pe_de_feijao.csv`) é disponibilizado de forma privada exclusivamente ao docente avaliador via Google Drive para realização dos testes de upload na plataforma.

---

## 🚀 4. Instalação e Execução

### Pré-requisitos
* Python 3.10 ou superior
* Pip e Virtualenv

### 1. Clonar ou Acessar o Diretório do Projeto
```bash
cd "c:\Users\klebe\OneDrive\Documentos\Pos Sis Seg For\6 - Projeto SI\Millena\Projeto Uncisal Ass Nutri"
```

### 2. Criar e Ativar Ambiente Virtual
```bash
python -m venv venv
# No Windows PowerShell:
.\venv\Scripts\Activate.ps1
# No Linux/macOS:
source venv/bin/activate
```

### 3. Instalar Dependências
```bash
pip install -r requirements.txt
```

### 4. Configurar Variáveis de Ambiente
Copie o arquivo `.env.example` para `.env` e configure sua chave da Groq:
```bash
cp .env.example .env
```
Edite o `.env`:
```ini
SECRET_KEY=sua_chave_secreta_aleatoria_aqui
ADMIN_USER=nutri
ADMIN_PASSWORD=nutri2026
GROQ_API_KEY=gsk_sua_chave_groq_aqui
PORT=5000
```

### 5. Executar a Aplicação
* **Modo de Desenvolvimento:**
  ```bash
  python app.py
  ```
* **Modo de Produção (Oracle Cloud com Gunicorn):**
  ```bash
  gunicorn -w 4 -b 0.0.0.0:5000 app:app
  ```

---

## 🧪 5. Testes Práticos e Demonstração

Para testar o fluxo completo:
1. Abra o navegador em `http://localhost:5000/login`.
2. Efetue login com o usuário `nutri` e a senha `nutri2026`.
3. Na tela principal (`painel.html`), clique na área de upload e selecione o arquivo de teste:
   `bioimpedancia_tanita_joao_do_pe_de_feijao.csv` *(disponibilizado de forma privada ao avaliador via Google Drive em razão do bloqueio de dados de saúde no `.gitignore`)*.
4. Clique em **"Processar Bioimpedância & Gerar Plano com IA"**.
5. Observe o laudo completo com os cards do Bloco 8, alerta de gordura do tronco (18.0%), as 6 refeições com os alimentos regionais (macaxeira, ovos, arroz, frango) e o botão de impressão para PDF.

---
**UNCISAL • Assessoria Nutricional Especializada • 2026**
