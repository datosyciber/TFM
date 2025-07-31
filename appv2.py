import streamlit as st
import requests
import time
import pandas as pd
import joblib
import ast
from collections import Counter
from sklearn.preprocessing import LabelEncoder, MultiLabelBinarizer
from fpdf import FPDF
import io
from io import BytesIO
import matplotlib.pyplot as plt

# ==== CARGA DE MODELOS Y DATOS ====
clf = joblib.load("clf.pkl")
le_family = joblib.load("le_family.pkl")
le_variant = joblib.load("le_variant.pkl")
mlb_tags = joblib.load("mlb_tags_vt.pkl")
mlb_sandbox = joblib.load("mlb_sandbox_class.pkl")
clf_columns = joblib.load("clf_columns.pkl")

# Clases preestablecidas a partir del conjunto de datos original
type_labels = {
    0: "Benign",
    1: "RedLineStealer",
    2: "Downloader",
    3: "RAT",
    4: "BankingTrojan",
    5: "SnakeKeyLogger",
    6: "Spyware"
}

# ==== FUNCIONES DE CONSULTA ====

# Consulta de APIs para obtener información del hash y que el modelo pueda predecir su clase
def consulta_vt(hash_val, api_key):
    headers = {'x-apikey': api_key}
    url = f'https://www.virustotal.com/api/v3/files/{hash_val}'
    r = requests.get(url, headers=headers)
    time.sleep(5)

    if r.status_code != 200:
        return {}

    data = r.json().get('data', {}).get('attributes', {})
    signature_data = data.get('signature_info', {})
    is_signed = bool(signature_data)
    signer = signature_data.get('signer', signature_data.get('publisher', 'Desconocido')) if is_signed else None

    pe_data = data.get('pe_info', {})
    ts = pe_data.get('timestamp')
    sections = pe_data.get('sections', [])
    entropy_avg = round(sum(s.get('entropy', 0) for s in sections) / len(sections), 2) if sections else None

    sandbox_data = data.get('sandbox_verdicts', {})
    malicious_count = 0
    confidences = []
    classifications = set()

    for verdict in sandbox_data.values():
        if verdict.get('category') == 'malicious':
            malicious_count += 1
            if 'confidence' in verdict:
                confidences.append(verdict['confidence'])
            classifications.update(verdict.get('malware_classification', []))

    confidence_avg = round(sum(confidences) / len(confidences), 2) if confidences else None

    return {
        'threat_label': data.get('popular_threat_classification', {}).get('suggested_threat_label', ''),
        'creation_date': data.get('creation_date'),
        'size': data.get('size'),
        'tags_vt': data.get('tags', []),
        'meaningful_name': data.get('meaningful_name'),
        'malicious_ratio': sum(
            1 for res in data.get('last_analysis_results', {}).values()
            if res.get('category') == 'malicious'
        ) / max(len(data.get('last_analysis_results', {})), 1),
        'sandbox_malicious_count': malicious_count,
        'sandbox_confidence_avg': confidence_avg,
        'sandbox_classifications': list(classifications),
        'is_signed': is_signed,
        'signature_entity': signer,
        'pe_compile_date': ts,
        'pe_entropy_avg': entropy_avg
    }


def consulta_otx(hash_val, api_key):
    headers = {"X-OTX-API-KEY": api_key}
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_val}/general"
    r = requests.get(url, headers=headers)
    time.sleep(1.5)

    if r.status_code != 200:
        return {}

    data = r.json()
    pulse_info = data.get('pulse_info', {})
    pulses = pulse_info.get('pulses', [])

    return {
        'pulse_names': {p.get('name', '') for p in pulses},
        'pulse_count': pulse_info.get('count', 0),
        'adversaries': list({p.get('adversary') for p in pulses if p.get('adversary')}),
        'attack_ids': list({(a.get('id'), a.get('name')) for p in pulses for a in p.get('attack_ids', []) if a.get('id') and a.get('name')})
    }


def consulta_ha_overview(hash_val, api_key):
    headers = {'api-key': api_key}
    url = f"https://www.hybrid-analysis.com/api/v2/overview/{hash_val}/summary"
    r = requests.get(url, headers=headers)
    time.sleep(15)

    if r.status_code != 200:
        return {}

    data = r.json()
    return {
        'verdict': data.get('verdict'),
        'multiscan_result': data.get('multiscan_result')
    }


# === PREPROCESAMIENTO DE DATOS ===

# Preprocesamiento para que se procese la información de forma óptima y mejorar la clasificación
def preprocesar_datos(datos):
    df = pd.DataFrame([datos])
    
    df['creation_date'] = pd.to_datetime(df['creation_date'], unit='s', errors='coerce')
    df['pe_compile_date'] = pd.to_datetime(df['pe_compile_date'], unit='s', errors='coerce')
    df['creation_year'] = df['creation_date'].dt.year
    df['creation_month'] = df['creation_date'].dt.month
    df['days_between_compile_creation'] = (df['creation_date'] - df['pe_compile_date']).dt.days

    df['is_signed'] = df['is_signed'].fillna(False).astype(bool).astype(int)

    df[['threat_type_raw', 'threat_variant']] = df['threat_label'].str.split('/', expand=True)
    df['threat_family'] = df['threat_type_raw'].str.extract(r'trojan\.([\w\d\-]+)', expand=False).fillna('unknown')
    df.drop(columns=['threat_type_raw'], inplace=True)

    df['threat_family_enc'] = le_family.transform(
        df['threat_family'].apply(lambda x: x if x in le_family.classes_ else 'other')
    )
    df['threat_variant_enc'] = le_variant.transform(
        df['threat_variant'].apply(lambda x: x if x in le_variant.classes_ else 'other')
    )

    pulses = df['pulse_names'].apply(lambda x: set(x) if isinstance(x, set) else set())
    pulse_groups = {
        'malware_hashes': ['Malware Hashes', 'Various Malware Families Hashes'],
        'malware_bazaar': ['Malware Bazaar 4', 'Malware Bazar 11', 'Malware Bazaar 7', 'Malwarebazaar 5', 'Malware bazaar 6'],
        'threatfox': ['Threatfox Recent Additions'],
        'agent_tesla': ['AgentTesla | 21-27.01.2022'],
        'c2_malware': ['C2 Servers & Virus Providers & Malware Hashes']
    }
    for group, names in pulse_groups.items():
        df[f'pulse_{group}'] = df['pulse_names'].apply(lambda x: int(any(p in x for p in names)))
    
    df['has_pulse'] = (df['pulse_count'] > 0).astype(int)

    for col, binarizer, prefix in [
        ('tags_vt', mlb_tags, 'tags_vt_'),
        ('sandbox_classifications', mlb_sandbox, 'sandbox_classifications_')
    ]:
        binarized = binarizer.transform(df[col])
        df_bin = pd.DataFrame(binarized, columns=[f"{prefix}{c}" for c in binarizer.classes_])
        df.reset_index(drop=True, inplace=True)
        df = pd.concat([df, df_bin], axis=1)
        df.drop(columns=[col], inplace=True)

    # Eliminar columnas no necesarias antes de la clasificación
    drop_cols = ['SHA256', 'meaningful_name', 'creation_date', 'pe_compile_date', 'threat_label',
             'verdict', 'adversaries', 'attack_ids', 'threat_type', 'threat_variant',
             'pulse_names', 'threat_family', 'signature_entity']
    df = df.drop(columns=[col for col in drop_cols if col in df.columns], errors='ignore')

    return df


class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 14)
        self.set_text_color(30, 30, 30)
        self.cell(0, 10, "Informe de Análisis de Hash", ln=True, align='C')
        self.ln(5)
        self.set_draw_color(180, 180, 180)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def section_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 10, f"{title}", ln=True, fill=True)
        self.ln(2)

    def section_body(self, keyvals):
        self.set_font("Arial", size=11)
        for key, val in keyvals.items():
            self.multi_cell(0, 8, f"{key}: {val}")
        self.ln(3)

# Con esta función se muestra el potencial de información mostrada en el informe de forma gráfica
def generar_grafico_pie(mal_ratio):
    fig, ax = plt.subplots(figsize=(2.5, 2.5))
    labels = ['Malicioso', 'No Malicioso']
    values = [mal_ratio, 1 - mal_ratio]
    colors = ['#FF6B6B', '#4CAF50']
    ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=140, colors=colors)
    ax.axis('equal')
    buf = BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    return buf


def generar_pdf(datos_raw, pred_label):
    pdf = PDF()
    pdf.add_page()

    pdf.set_font("Arial", size=12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, f"Hash: {datos_raw.get('SHA256', '')}", ln=True)
    pdf.set_font("Arial", 'B', 12)
    pdf.set_text_color(220, 50, 50)
    pdf.cell(0, 10, f"Clasificación del modelo: {pred_label}", ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    #--- Sección 1: Información General ---
    pdf.section_title("Información General")
    pdf.section_body({
        "Nombre": datos_raw.get("meaningful_name", "Desconocido"),
        "Tamaño (bytes)": datos_raw.get("size", "N/A"),
        "Compilado": datos_raw.get("pe_compile_date", "N/A"),
        "Firmado": str(datos_raw.get("is_signed", False)),
        "Entidad Firma": datos_raw.get("signature_entity", "N/A"),
        "Entropía PE promedio": datos_raw.get("pe_entropy_avg", "N/A")
    })

    #--- Sección 2: VirusTotal ---
    pdf.section_title("Análisis en VirusTotal")
    pdf.section_body({
        "Etiquetas": ', '.join(datos_raw.get("tags_vt", [])),
        "Ratio detección maliciosa": f"{round(datos_raw.get('malicious_ratio', 0)*100, 2)}%",
        "Clasificación sugerida": datos_raw.get("threat_label", "N/A")
    })

    #--- Elemento gráfico: gráfico de tarta ---
    pie_buf = generar_grafico_pie(datos_raw.get('malicious_ratio', 0))
    pie_path = "pie_chart.png"
    with open(pie_path, "wb") as f:
        f.write(pie_buf.read())
    pdf.image(pie_path, x=70, w=70)
    pdf.ln(10)

    #--- Sección 3: Análisis dinámico ---
    pdf.section_title("Análisis dinámico")
    pdf.section_body({
        "Clasificaciones": ', '.join(datos_raw.get("sandbox_classifications", [])),
        "Confianza media": datos_raw.get("sandbox_confidence_avg", "N/A"),
        "Conteo veredictos maliciosos": datos_raw.get("sandbox_malicious_count", "N/A")
    })

    #--- Sección 4: HA ---
    pdf.section_title("Datos de OTX y Hybrid Analysis")
    pdf.section_body({
        "Pulses encontrados": datos_raw.get("pulse_count", 0),
        "Adversarios": ', '.join(datos_raw.get("adversaries", [])),
        "Veredicto HA": datos_raw.get("verdict", "N/A"),
        "Resultado Multiscan": datos_raw.get("multiscan_result", "N/A")
    })

    # Esta parte sirve para exportar a bytes para Streamlit
    pdf_bytes = pdf.output(dest='S').encode('latin1')
    return BytesIO(pdf_bytes)


# === APLICACIÓN ===

st.title("Malware Hash Analyzer con Machine Learning")
st.write("Introduce un hash de archivo y tus claves API para obtener una predicción de amenaza.")

with st.sidebar:
    vt_key = st.text_input("API Key - VirusTotal", type="password")
    otx_key = st.text_input("API Key - OTX", type="password")
    ha_key = st.text_input("API Key - HybridAnalysis", type="password")

hash_input = st.text_input("Hash del archivo")

if st.button("Analizar"):
    if not all([vt_key, otx_key, ha_key]):
        st.error("Debes introducir todas las claves API.")
    elif not hash_input:
        st.warning("Introduce un hash para continuar.")
    else:
        with st.spinner("Consultando fuentes y procesando..."):
            vt_data = consulta_vt(hash_input, vt_key)
            otx_data = consulta_otx(hash_input, otx_key)
            ha_data = consulta_ha_overview(hash_input, ha_key)

            if not vt_data:
                st.error("Error al consultar VirusTotal.")
            else:
                datos = {**vt_data, **otx_data, **ha_data, 'SHA256': hash_input}
                X = preprocesar_datos(datos)
                X = X[clf_columns]
                pred = clf.predict(X)[0]
                pred_label = type_labels.get(pred)

                # Guardar en el estado de la sesión: esto es importante porque de lo contrario, no se almacena la información y no se puede generar seguidamente el informe
                st.session_state["datos"] = datos
                st.session_state["pred_label"] = pred_label
                st.session_state["hash"] = hash_input


# Mostrar resultados si existen
if "pred_label" in st.session_state:
    st.success(f"Clasificación del archivo: **{st.session_state['pred_label']}**")

    if st.button("Generar informe"):
        pdf_bytes = generar_pdf(st.session_state["datos"], st.session_state["pred_label"])
        st.download_button(
            label="Descargar Informe PDF",
            data=pdf_bytes,
            file_name=f"hash_report_{st.session_state['hash']}.pdf",
            mime="application/pdf"
        )
