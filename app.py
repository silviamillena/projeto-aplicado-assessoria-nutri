from flask import Flask, render_template, request, flash, redirect, session
from werkzeug.utils import secure_filename
from functools import wraps
import os
import json
import csv
import html
import hmac
import uuid
import secrets
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime
from dotenv import load_dotenv
import markdown
from markupsafe import Markup

# ==============================================================================
# PROJETO APLICADO: PRÁTICAS DE MERCADO - UNCISAL
# ALUNA: Silvia Millena Rocha Torres
# SISTEMA DE ASSESSORIA DE NUTRIÇÃO CLÍNICA E ESPORTIVA (BIOIMPEDÂNCIA TANITA 8 ELETRODOS)
# ==============================================================================

# Carrega variáveis de ambiente a partir do arquivo .env
load_dotenv()

# Leitura da credencial da API Groq Cloud (OWASP A02:2025 - Security Misconfiguration)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

try:
    from openai import OpenAI
    HAS_OPENAI = True
    # Inicializa o cliente apontando diretamente para o gateway da Groq
    client = OpenAI(
        api_key=GROQ_API_KEY,
        base_url="https://api.groq.com/openai/v1"
    )
except Exception:
    OpenAI = None
    HAS_OPENAI = False
    client = None

try:
    import pandas as pd
    HAS_PANDAS = True
except Exception:
    pd = None
    HAS_PANDAS = False

app = Flask(__name__)

# Configurações Explícitas de Segurança para Cookies de Sessão (OWASP A01:2025 / A07:2025)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=True 
)

# Mitigação OWASP A02/A04: Chave de sessão configurada via ambiente para evitar adulteração de cookies
# Se SECRET_KEY não for informada no .env, gera uma chave criptográfica forte dinamicamente
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)

# Mitigação OWASP A01/A07: ProxyFix para Nginx na Oracle Cloud (previne IP Spoofing em Rate Limiting)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# --- CINTURÃO DE SEGURANÇA E PROTEÇÃO DE ARQUIVOS (OWASP TOP 10:2025) ---
# Mitigação OWASP A06:2025 (Insecure Design) - Limitação estrita do tamanho de payload (2MB) contra DoS
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ARQUIVO_PACIENTE = 'dados_paciente.json'

# Mitigação OWASP A10:2025: Tratamento de exceção para arquivos que excedem o tamanho máximo permitido
@app.errorhandler(413)
def request_entity_too_large(error):
    flash('Bloqueio de Segurança: O arquivo enviado excede o limite máximo permitido de 2MB.', 'error')
    return redirect('/')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def carregar_dados_paciente():
    if os.path.exists(ARQUIVO_PACIENTE):
        try:
            with open(ARQUIVO_PACIENTE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def salvar_dados_paciente(dados):
    try:
        with open(ARQUIVO_PACIENTE, 'w', encoding='utf-8') as f:
            json.dump(dados, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Erro ao persistir dados do paciente: {e}")

# --- MITIGAÇÃO OWASP A01:2025 (Broken Access Control) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logado' not in session:
            flash('Acesso negado. Por favor, autentique-se para acessar o painel de nutrição.', 'error')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# --- MITIGAÇÃO OWASP A07:2025 (Authentication Failures / Força Bruta) ---
TENTATIVAS_FALHAS = {}

def obter_ip_cliente():
    return request.remote_addr or '127.0.0.1'

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = obter_ip_cliente()
    agora = datetime.now().timestamp()
    
    # Limpeza de tentativas expiradas (janela de monitoramento: 5 minutos = 300 segundos)
    if ip in TENTATIVAS_FALHAS and (agora - TENTATIVAS_FALHAS[ip]['tempo']) > 300:
        del TENTATIVAS_FALHAS[ip]
        
    # Bloqueio com HTTP 429 se exceder 4 tentativas incorretas em 300 segundos
    if ip in TENTATIVAS_FALHAS and TENTATIVAS_FALHAS[ip]['count'] >= 4:
        return "Too Many Requests - Bloqueio de Segurança Temporário (Rate Limit Excedido: 4 tentativas falhas em 300 segundos). Aguarde para tentar novamente.", 429

    if request.method == 'POST':
        usuario = request.form.get('usuario', '')
        senha = request.form.get('senha', '')
        
        ADMIN_USER = os.getenv("ADMIN_USER")
        ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
        
        if not ADMIN_USER or not ADMIN_PASSWORD:
            flash('Erro de Configuração de Segurança: As credenciais do sistema não foram configuradas no arquivo .env.', 'error')
            return render_template('login.html')
        
        # Mitigação OWASP A07:2025: Comparação em tempo constante contra Timing Attacks
        if hmac.compare_digest(usuario, ADMIN_USER) and hmac.compare_digest(senha, ADMIN_PASSWORD):
            session.clear()  # Mitigação OWASP contra Session Fixation
            session['logado'] = True
            session['usuario'] = usuario
            if ip in TENTATIVAS_FALHAS:
                del TENTATIVAS_FALHAS[ip]
            flash('Autenticação realizada com sucesso. Bem-vindo(a) ao painel clínico!', 'success')
            return redirect('/')
        else:
            if ip not in TENTATIVAS_FALHAS:
                TENTATIVAS_FALHAS[ip] = {'count': 1, 'tempo': agora}
            else:
                TENTATIVAS_FALHAS[ip]['count'] += 1
                TENTATIVAS_FALHAS[ip]['tempo'] = agora
            restantes = max(0, 4 - TENTATIVAS_FALHAS[ip]['count'])
            flash(f'Credenciais inválidas. Tentativas restantes antes do bloqueio temporário: {restantes}', 'error')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Sessão encerrada com sucesso.', 'success')
    return redirect('/login')

# --- ROTAS PRINCIPAIS PROTEGIDAS ---
@app.route('/')
@login_required
def painel():
    dados = carregar_dados_paciente()
    tem_plano_anterior = bool(dados.get("ultimo_plano_html"))
    paciente_anterior = dados.get("paciente_info", {})
    bloco8 = dados.get("bloco8", {})
    modo_historico = session.get('modo_historico', False)
    
    return render_template('painel.html', 
                           tem_plano_anterior=tem_plano_anterior, 
                           paciente_anterior=paciente_anterior,
                           bloco8=bloco8,
                           modo_historico=modo_historico,
                           dados_completos=dados if modo_historico else {})

@app.route('/nova_avaliacao')
@login_required
def nova_avaliacao():
    usuario = session.get('usuario')
    session.clear()
    session['logado'] = True
    session['usuario'] = usuario
    session['modo_historico'] = False
    flash('Nova avaliação iniciada! Painel limpo e pronto para o upload de um novo exame CSV.', 'success')
    return redirect('/')

@app.route('/carregar_historico')
@login_required
def carregar_historico():
    dados = carregar_dados_paciente()
    if not dados or not dados.get("paciente_info"):
        flash('Nenhum histórico anterior encontrado em dados_paciente.json. Por favor, envie um novo arquivo CSV.', 'error')
        session['modo_historico'] = False
        return redirect('/')
    
    session['modo_historico'] = True
    nome_paciente = dados.get("paciente_info", {}).get("nome_paciente", "Cadastrado")
    flash(f'Histórico do paciente "{nome_paciente}" carregado com sucesso! Confira o resumo dos dados abaixo.', 'success')
    return redirect('/')

def converter_float(valor, padrao=0.0):
    try:
        if valor is None:
            return padrao
        return float(str(valor).strip().replace(',', '.'))
    except (ValueError, TypeError):
        return padrao

def converter_int(valor, padrao=0):
    try:
        if valor is None:
            return padrao
        return int(float(str(valor).strip().replace(',', '.')))
    except (ValueError, TypeError):
        return padrao

def ler_e_normalizar_csv(caminho_arquivo):
    """
    Lê o CSV com suporte a detecção de encoding (utf-8-sig / latin-1) e normaliza
    casos onde o Excel envolve linhas inteiras com aspas duplas externas.
    Suporta Pandas e fallback nativo para csv.reader.
    """
    encoding = 'utf-8-sig'
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8-sig') as f:
            f.read(2048)
    except UnicodeDecodeError:
        encoding = 'latin-1'

    # Tratamento para linhas com aspas duplas externas geradas por edições no Excel
    linhas_sanitizadas = []
    with open(caminho_arquivo, 'r', encoding=encoding) as f:
        for linha in f:
            l = linha.strip()
            if not l:
                continue
            # Se a linha inteira foi salva envolvida em aspas pelo Excel
            if l.startswith('"') and l.endswith('"') and ',' in l and not l.startswith('"""'):
                l = l[1:-1].replace('""', '"')
            linhas_sanitizadas.append(l)

    # Regrava arquivo limpo para leitura uniforme
    with open(caminho_arquivo, 'w', encoding='utf-8', newline='') as f:
        f.write('\n'.join(linhas_sanitizadas))

    dados_dict = {}
    colunas = []
    linhas_matriz = []

    if HAS_PANDAS and pd is not None:
        try:
            df = pd.read_csv(caminho_arquivo)
            df.columns = [c.strip() for c in df.columns]
            colunas = list(df.columns)
            if not df.empty:
                primeira_linha = df.iloc[0].to_dict()
                dados_dict = {str(k).strip(): ('' if pd.isna(v) else str(v).strip()) for k, v in primeira_linha.items()}
                linhas_matriz = df.head(10).values.tolist()
        except Exception as e_pandas:
            print(f"Aviso de parsing com Pandas ({e_pandas}). Alternando para o módulo nativo csv...")
            dados_dict = {}

    if not dados_dict:
        with open(caminho_arquivo, 'r', encoding='utf-8', newline='') as f:
            reader = csv.reader(f)
            todas_linhas = [r for r in reader if r]
            if todas_linhas:
                colunas = [c.strip() for c in todas_linhas[0]]
                if len(todas_linhas) > 1:
                    valores = [v.strip() for v in todas_linhas[1]]
                    dados_dict = dict(zip(colunas, valores))
                    linhas_matriz = todas_linhas[1:10]

    return colunas, linhas_matriz, dados_dict

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('Nenhum arquivo detectado pelo sistema.', 'error')
        return redirect('/')
    
    file = request.files['file']
    
    if file.filename == '':
        flash('Nenhum arquivo selecionado.', 'error')
        return redirect('/')
    
    if file and allowed_file(file.filename):
        # Mitigação OWASP A06:2025: Nome de arquivo estocástico com UUID para neutralizar Path Traversal e colisão
        nome_seguro = secure_filename(file.filename)
        filename = f"{uuid.uuid4().hex}_{nome_seguro}"
        caminho_salvo = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(caminho_salvo)
        
        try:
            colunas, linhas_matriz, dados_dict = ler_e_normalizar_csv(caminho_salvo)

            if not dados_dict:
                flash('Erro de leitura: O arquivo CSV fornecido está vazio ou com formato ilegível.', 'error')
                return redirect('/')

            # Seletores Clínicos enviados via formulário
            estrategia_calorica_form = html.escape(request.form.get('estrategia_calorica_form', '').strip())
            nivel_atividade_form = html.escape(request.form.get('nivel_atividade_form', '').strip())
            restricoes_clinicas_raw = request.form.getlist('restricoes_clinicas_form')
            restricoes_clinicas_form = [html.escape(r.strip()) for r in restricoes_clinicas_raw if r.strip()]

            if not restricoes_clinicas_form:
                restricoes_clinicas_form = ["Nenhuma restrição clínica ou alimentar"]
            elif len(restricoes_clinicas_form) > 1 and "Nenhuma restrição clínica ou alimentar" in restricoes_clinicas_form:
                restricoes_clinicas_form = [r for r in restricoes_clinicas_form if r != "Nenhuma restrição clínica ou alimentar"]

            # Extração dos 33 parâmetros fisiológicos da bioimpedância Tanita
            id_paciente = dados_dict.get('id_paciente', 'PAC-001')
            nome_paciente = dados_dict.get('nome_paciente', 'Paciente Não Identificado')
            idade = converter_int(dados_dict.get('idade', 37))
            sexo_biologico = dados_dict.get('sexo_biologico', 'Masculino')
            altura_cm = converter_float(dados_dict.get('altura_cm', 178.0))
            peso_kg = converter_float(dados_dict.get('peso_kg', 74.7))
            imc_calculado = converter_float(dados_dict.get('imc_calculado', 23.58))
            objetivo_principal = dados_dict.get('objetivo_principal', 'Emagrecimento (Definicao / Secar Tronco)')
            
            # Prioriza a estratégia calórica selecionada no formulário pelo Nutricionista
            estrategia_calorica = estrategia_calorica_form if estrategia_calorica_form else dados_dict.get('estrategia_calorica', 'Dieta Hipocalorica')
            
            tmb_tanita_kcal = converter_int(dados_dict.get('tmb_tanita_kcal', 1784))
            idade_metabolica_anos = converter_int(dados_dict.get('idade_metabolica_anos', 23))
            perc_gordura_total = converter_float(dados_dict.get('perc_gordura_total', 14.8))
            perc_agua_corporal = converter_float(dados_dict.get('perc_agua_corporal', 59.0))
            massa_muscular_total_kg = converter_float(dados_dict.get('massa_muscular_total_kg', 59.9))
            massa_ossea_estimada_kg = converter_float(dados_dict.get('massa_ossea_estimada_kg', 3.2))
            gordura_visceral_rating = converter_int(dados_dict.get('gordura_visceral_rating', 5))
            perc_gordura_braco_esq = converter_float(dados_dict.get('perc_gordura_braco_esq', 11.5))
            perc_gordura_braco_dir = converter_float(dados_dict.get('perc_gordura_braco_dir', 11.7))
            perc_gordura_perna_esq = converter_float(dados_dict.get('perc_gordura_perna_esq', 11.8))
            perc_gordura_perna_dir = converter_float(dados_dict.get('perc_gordura_perna_dir', 11.7))
            perc_gordura_tronco = converter_float(dados_dict.get('perc_gordura_tronco', 18.0))
            meta_agua_litros_dia = converter_float(dados_dict.get('meta_agua_litros_dia', 3.4))
            agua_jejum_ml = converter_int(dados_dict.get('agua_jejum_ml', 200))
            num_refeicoes_dia = converter_int(dados_dict.get('num_refeicoes_dia', 6))
            horarios_refeicoes = dados_dict.get('horarios_refeicoes', '06:00-08:00 | 10:00 | 12:00-13:00 | 15:00-16:00 | 18:00-19:00 | 21:00-22:00')
            alimentos_regionais_preferidos = dados_dict.get('alimentos_regionais_preferidos', 'Macaxeira, Pao integral, Ovos, Mussarela, Arroz, Feijao, Macarrao, Carne, Frango, Peixe, Banana, Maca, Uva, Castanha de caju, Amendoim')
            restricoes_vegetais_alto_ig = dados_dict.get('restricoes_vegetais_alto_ig', 'Batata inglesa, Abobora')
            metodo_pesagem_alimentos = dados_dict.get('metodo_pesagem_alimentos', 'Alimento pronto/cozido')
            adocantes_permitidos = dados_dict.get('adocantes_permitidos', 'Stevia, Sucralose, Xilitol (4 a 6 gotas)')
            suplementacao_prescrita = dados_dict.get('suplementacao_prescrita', 'Creatina 3g/dia | Omega 3 1g pos-almoco | Whey Protein 30g com agua pos-treino')
            protocolo_pre_treino = dados_dict.get('protocolo_pre_treino', '2 frutas a livre escolha antes do treino')
            frequencia_monitoramento_peso = dados_dict.get('frequencia_monitoramento_peso', 'Semanal')
            retorno_consulta = dados_dict.get('retorno_consulta', 'Julho')

            # --- CÁLCULOS FISIOLÓGICOS DO BLOCO 8 ---
            massa_gorda_kg = round(peso_kg * (perc_gordura_total / 100.0), 2)
            massa_livre_gordura_kg = round(peso_kg - massa_gorda_kg, 2)
            tmb_katch_kcal = round(370 + (21.6 * massa_muscular_total_kg))
            media_membros = round((perc_gordura_braco_esq + perc_gordura_braco_dir + perc_gordura_perna_esq + perc_gordura_perna_dir) / 4.0, 2)

            if perc_gordura_tronco - media_membros >= 3.0:
                alerta_segmental = "Atenção: Concentração adiposa no Tronco superior à média dos membros. Simetria muscular preservada entre lados D/E."
            else:
                alerta_segmental = "Distribuição adiposa equilibrada entre tronco e membros periféricos. Simetria muscular preservada entre lados D/E."

            # Extração do fator de atividade e cálculo de GET e Meta Calórica
            fator_atividade = 1.55
            if "1.2" in nivel_atividade_form and "1.375" not in nivel_atividade_form and "1.725" not in nivel_atividade_form:
                fator_atividade = 1.2
            elif "1.375" in nivel_atividade_form:
                fator_atividade = 1.375
            elif "1.55" in nivel_atividade_form:
                fator_atividade = 1.55
            elif "1.725" in nivel_atividade_form:
                fator_atividade = 1.725
            elif "1.9" in nivel_atividade_form:
                fator_atividade = 1.9

            get_kcal = round(tmb_katch_kcal * fator_atividade)
            
            estrategia_lower = estrategia_calorica.lower()
            if "hipocal" in estrategia_lower or "-400" in estrategia_lower:
                meta_calorica_kcal = get_kcal - 400
            elif "hipercal" in estrategia_lower or "+400" in estrategia_lower:
                meta_calorica_kcal = get_kcal + 400
            else:
                meta_calorica_kcal = get_kcal

            # Dicionário do Bloco 8 para a interface gráfica
            bloco8 = {
                "massa_gorda_kg": massa_gorda_kg,
                "massa_livre_gordura_kg": massa_livre_gordura_kg,
                "tmb_katch_kcal": tmb_katch_kcal,
                "tmb_tanita_kcal": tmb_tanita_kcal,
                "media_membros": media_membros,
                "perc_gordura_tronco": perc_gordura_tronco,
                "alerta_segmental": alerta_segmental,
                "idade_metabolica_anos": idade_metabolica_anos,
                "gordura_visceral_rating": gordura_visceral_rating,
                "perc_agua_corporal": perc_agua_corporal,
                "meta_agua_litros_dia": meta_agua_litros_dia,
                "peso_kg": peso_kg,
                "imc_calculado": imc_calculado,
                "massa_muscular_total_kg": massa_muscular_total_kg,
                "fator_atividade": fator_atividade,
                "nivel_atividade": nivel_atividade_form or "Moderadamente Ativo (1.55)",
                "get_kcal": get_kcal,
                "meta_calorica_kcal": meta_calorica_kcal,
                "estrategia_calorica": estrategia_calorica,
                "restricoes_clinicas": restricoes_clinicas_form
            }

            paciente_info = {
                "id_paciente": id_paciente,
                "nome_paciente": nome_paciente,
                "idade": idade,
                "sexo_biologico": sexo_biologico,
                "objetivo_principal": objetivo_principal,
                "estrategia_calorica": estrategia_calorica,
                "retorno_consulta": retorno_consulta,
                "nivel_atividade": nivel_atividade_form or "Moderadamente Ativo (1.55)",
                "get_kcal": get_kcal,
                "meta_calorica_kcal": meta_calorica_kcal,
                "restricoes_clinicas": ", ".join(restricoes_clinicas_form)
            }

            # Mitigação OWASP A05:2025: Sanitização contra Cross-Site Scripting (XSS) na tabela de visualização
            th_html = "".join(f"<th>{html.escape(str(c))}</th>" for c in colunas)
            tb_html = "".join(
                "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>"
                for row in linhas_matriz
            )
            tabela_html = f'<table class="tabela-tanita"><thead><tr>{th_html}</tr></thead><tbody>{tb_html}</tbody></table>'

            # --- CONSTRUÇÃO DO PROMPT CLÍNICO DA IA (GROQ) ---
            prompt_ia = f"""Atue como um Nutricionista Clínico e Esportivo Especialista em Bioimpedância Segmental Tanita (8 eletrodos).
Com base nos dados laboratoriais e fisiológicos do paciente abaixo, elabore um Plano e Rascunho Clínico Individualizado de 3 meses.

DADOS DO PACIENTE E BIOIMPEDÂNCIA TANITA:
- Identificação: {nome_paciente} ({id_paciente}) | Sexo: {sexo_biologico} | Idade: {idade} anos
- Estatura: {altura_cm} cm | Peso Atual: {peso_kg} kg | IMC: {imc_calculado} kg/m²
- Objetivo Clínico: {objetivo_principal}
- Estratégia Calórica Prescrita: {estrategia_calorica}
- Taxa Metabólica Basal (Tanita): {tmb_tanita_kcal} kcal/dia
- Idade Metabólica: {idade_metabolica_anos} anos (vs {idade} anos cronológicos)
- Composição Corporal: Gordura Total: {perc_gordura_total}% | Massa Muscular: {massa_muscular_total_kg} kg | Massa Óssea: {massa_ossea_estimada_kg} kg | Água Corporal: {perc_agua_corporal}%
- Nível de Gordura Visceral: Nível {gordura_visceral_rating}
- Avaliação Segmental:
  * Braço Esquerdo: {perc_gordura_braco_esq}% | Braço Direito: {perc_gordura_braco_dir}%
  * Perna Esquerda: {perc_gordura_perna_esq}% | Perna Direita: {perc_gordura_perna_dir}%
  * Tronco: {perc_gordura_tronco}%

PARÂMETROS CALCULADOS (BLOCO 8) & GASTO ENERGÉTICO:
- Massa Gorda Total: {massa_gorda_kg} kg
- Massa Livre de Gordura (MLG): {massa_livre_gordura_kg} kg
- Taxa Metabólica Basal (Equação Katch-McArdle): {tmb_katch_kcal} kcal/dia
- Nível de Atividade Física: {nivel_atividade_form or "Moderadamente Ativo (1.55)"} (Fator Fisiológico: {fator_atividade})
- Gasto Energético Total (GET): {get_kcal} kcal/dia
- Meta Calórica Alvo Prescrita: {meta_calorica_kcal} kcal/dia
- Média de Gordura nos 4 Membros Periféricos: {media_membros}%
- Avaliação de Dispersão Segmental: {alerta_segmental}

PRESCRIÇÕES, PREFERÊNCIAS E CONDIÇÕES CLÍNICAS:
- Condições Clínicas e Restrições Alimentares Ativas: {", ".join(restricoes_clinicas_form)}
- Hidratação: Meta diária de {meta_agua_litros_dia} Litros/dia ({agua_jejum_ml}ml imediatamente ao acordar em jejum).
- Frequência Alimentar: {num_refeicoes_dia} refeições ao dia. Horários: {horarios_refeicoes}
- Alimentos Regionais Preferidos: {alimentos_regionais_preferidos}
- Restrições Estritas de Vegetais (Alto Índice Glicêmico): {restricoes_vegetais_alto_ig}
- Método de Pesagem dos Alimentos: {metodo_pesagem_alimentos}
- Adoçantes Permitidos: {adocantes_permitidos}
- Suplementação Prescrita: {suplementacao_prescrita}
- Protocolo Pré-Treino: {protocolo_pre_treino}
- Monitoramento de Peso: Frequência {frequencia_monitoramento_peso}
- Retorno da Consulta: {retorno_consulta}

DIRETRIZES OBRIGATÓRIAS DE ESTRUTURAÇÃO DO DOCUMENTO (FORMATO MARKDOWN):
1. SELO OBRIGATÓRIO NO TOPO:
Deve iniciar impreterivelmente com:
[RASCUNHO CLÍNICO GERADO POR IA — EXCLUSIVO PARA REVISÃO E RATIFICAÇÃO DO NUTRICIONISTA | DADOS PROTEGIDOS PELA LGPD]

2. RESUMO DA CONSULTA E INTERPRETAÇÃO DA BIOIMPEDÂNCIA:
- Comparar a TMB Tanita ({tmb_tanita_kcal} kcal) com a TMB Katch-McArdle ({tmb_katch_kcal} kcal), explicando o GET ({get_kcal} kcal) e a Meta Calórica Alvo de {meta_calorica_kcal} kcal/dia de acordo com a estratégia ({estrategia_calorica}).
- Analisar a Idade Metabólica de {idade_metabolica_anos} anos vs idade cronológica de {idade} anos.
- Detalhar a hidratação diária de {meta_agua_litros_dia}L/dia ({agua_jejum_ml}ml em jejum).
- Analisar o foco na gordura do tronco ({perc_gordura_tronco}% vs {media_membros}% nos membros), validando simetria muscular.

3. ADAPTAÇÕES CLÍNICAS E PATOLÓGICAS MANDATÓRIAS:
Condições/restrições clínicas selecionadas: {", ".join(restricoes_clinicas_form)}.
Você DEVE adaptar rigorosamente os alimentos recomendados a estas diretrizes:
* Se Hipertensão Arterial: restrinja sódio estritamente (<2000mg/dia), elimine embutidos e aplique protocolo DASH com ervas naturais.
* Se Diabetes / Resistência à Insulina: controle estrito do índice glicêmico (baixo IG), proibição de açúcares simples e aumento de fibras solúveis.
* Se Dislipidemia (Colesterol/Triglicerídeos): restrinja gorduras saturadas (<7% do VET), exclua gorduras trans e enfatize gorduras boas (azeite, oleaginosas, ômega 3).
* Se Intolerância à Lactose: exclua produtos lácteos com lactose (queijo comum, leite, whey concentrado com lactose); substitua por queijos maturados zero lactose, tofu ou opções vegetais.
* Se Sensibilidade ao Glúten / Gastrite / Refluxo: substitua trigo por macaxeira, arroz ou aveia sem glúten; elimine irritantes gástricos (pimenta, excesso de café, frituras).
* Se Nenhuma restrição clínica: siga o equilíbrio nutricional esportivo com os alimentos regionais preferidos.

4. TABELA DO PROGRAMA ALIMENTAR INDIVIDUALIZADO (6 REFEIÇÕES):
Apresentar uma tabela estruturada em Markdown com as colunas: Refeição | Horário Sugerido | Alimentos & Quantidades | Observações Clínicas.
Obrigatório cobrir:
- Café da Manhã: 200ml de água em jejum + 3 opções equivalentes (Opção 1 com pão integral e ovos mexidos; Opção 2 com 100g de macaxeira e ovos mexidos; Opção 3 com omelete). *Adequar lactose/glúten se necessário*.
- Lanche da Manhã: Frutas selecionadas (banana, maçã ou uva).
- Almoço: 100g de carboidrato (arroz, feijão ou macarrão) + 140g de carne, frango ou peixe + 2 porções de vegetais (restrição expressa: NUNCA prescrever {restricoes_vegetais_alto_ig}).
- Lanche da Tarde: Frutas práticas ou opções compatíveis com a rotina.
- Jantar: Permitir repetir as opções do Café da Manhã ou a estrutura do Almoço.
- Ceia: 1 fruta leve ou 40g de castanha de caju ou amendoim.

5. PROTOCOLO DE SUPLEMENTAÇÃO E DIRETRIZES TÉCNICAS:
- Creatina: 3g/dia (uso diário contínuo).
- Ômega 3: 1g após o almoço.
- Whey Protein: 30g com água imediatamente pós-treino (versão isolada sem lactose se intolerante).
- Pré-Treino: 2 frutas a livre escolha.
- Modo de Pesagem: Todo alimento deve ser pesado pronto/cozido em balança de precisão.
- Adoçantes Permitidos: Stevia, Sucralose ou Xilitol (4 a 6 gotas).

6. ESTRUTURA DO PLANO DE 3 MESES E ASSINATURA:
- Fase 1 (Mês 1 - Adaptação e Déficit Inicial): Estabilização metabólica, adesão à pesagem de alimentos e depleção de glicogênio.
- Fase 2 (Mês 2 - Otimização e Lipólise Tronco): Oxidação lipídica acentuada na região visceral e tronco.
- Fase 3 (Mês 3 - Consolidação e Definição): Manutenção de massa muscular, ajuste fino de macronutrientes e preparação para a reavaliação.
- Campo formal para Assinatura e Carimbo do Nutricionista com CRM/CRN e data de retorno para {retorno_consulta}.
"""

            # --- CHAMADA À GROQ COM FALLBACK DE MODELOS E PROTOCOLO HTTP ---
            modelos_seguros = [
                "qwen/qwen3.8-27b",
                "openai/gpt-oss-20b",
                "llama-3.3-70b-versatile"
            ]

            analise_ia = None

            for modelo_tentativa in modelos_seguros:
                try:
                    if HAS_OPENAI and client is not None:
                        resposta = client.chat.completions.create(
                            model=modelo_tentativa,
                            messages=[{"role": "user", "content": prompt_ia}],
                            max_tokens=3500
                        )
                        analise_ia = resposta.choices[0].message.content
                        break
                    else:
                        import urllib.request
                        req = urllib.request.Request(
                            "https://api.groq.com/openai/v1/chat/completions",
                            headers={
                                "Authorization": f"Bearer {GROQ_API_KEY}",
                                "Content-Type": "application/json"
                            },
                            data=json.dumps({
                                "model": modelo_tentativa,
                                "messages": [{"role": "user", "content": prompt_ia}],
                                "max_tokens": 3500
                            }).encode("utf-8")
                        )
                        with urllib.request.urlopen(req, timeout=45) as resp:
                            dados_resp = json.loads(resp.read().decode("utf-8"))
                            analise_ia = dados_resp["choices"][0]["message"]["content"]
                            break
                except Exception as e_ia:
                    print(f"Aviso interno: Falha no modelo {modelo_tentativa} ({str(e_ia)}). Tentando próximo da lista...")
                    continue

            if not analise_ia:
                flash('Aviso do Sistema: Os modelos de Inteligência Artificial da Groq estão temporariamente instáveis. O prompt fisiológico foi gerado para análise.', 'error')

            if analise_ia:
                html_gerado = markdown.markdown(analise_ia, extensions=['tables'])
                analise_html = Markup(html_gerado)
            else:
                analise_html = None
                html_gerado = ""

            tabela_markup = Markup(tabela_html)

            # Persistência do plano gerado para consulta subsequente
            dados_salvos = {
                "ultimo_plano_html": html_gerado,
                "ultimo_prompt": prompt_ia,
                "ultima_tabela_html": tabela_html,
                "bloco8": bloco8,
                "paciente_info": paciente_info,
                "data_processamento": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            }
            salvar_dados_paciente(dados_salvos)
            session['modo_historico'] = True

            return render_template('analise.html', 
                                   prompt=prompt_ia, 
                                   resposta=analise_html, 
                                   tabela=tabela_markup, 
                                   bloco8=bloco8, 
                                   paciente=paciente_info)

        except Exception as e:
            flash(f'Erro ao processar os dados da bioimpedância: {str(e)}', 'error')
            return redirect('/')

    else:
        flash('Bloqueio de Segurança: Apenas arquivos com extensão .csv são aceitos pelo sistema.', 'error')
        return redirect('/')

@app.route('/plano_atual')
@login_required
def plano_atual():
    dados = carregar_dados_paciente()
    if dados.get("ultimo_plano_html"):
        analise_html = Markup(dados["ultimo_plano_html"])
        tabela_html = Markup(dados.get("ultima_tabela_html", ""))
        prompt_ia = dados.get("ultimo_prompt", "")
        bloco8 = dados.get("bloco8", {})
        paciente_info = dados.get("paciente_info", {})
        return render_template('analise.html', 
                               prompt=prompt_ia, 
                               resposta=analise_html, 
                               tabela=tabela_html, 
                               bloco8=bloco8, 
                               paciente=paciente_info)
    else:
        flash('Nenhum plano alimentar gerado anteriormente. Realize o upload de um arquivo CSV da Tanita para iniciar a avaliação.', 'error')
        return redirect('/')

if __name__ == '__main__':
    # Mitigação OWASP A02:2025: debug=False para impedir execução remota e vazamento de stacktrace
    porta = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=porta, debug=False)

