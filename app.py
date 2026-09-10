import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, request
import joblib
import pandas as pd
from urllib.parse import urlparse
from feature_extractor import extract_features

app = Flask(__name__)
model = joblib.load(r"D:\skripsi\dataset2\skripsi_sistem\best_prediction_model_fix.pkl")

# validasi manual url
def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False
        

# pengecekan format
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form.get("url")

        # cek input kosong
        if not url:
            result = {"error": "URL tidak boleh kosong"}

        # cek format url
        elif not is_valid_url(url):
            result = {"error": "Masukkan URL dengan format yang benar "}

        else:
            feats = extract_features(url)

            if feats is None:
                result = {"error": "Halaman tidak bisa diakses atau bukan HTML"}
            else:
                try:
                    # fitur sesuai model
                    feature_values = [
                        feats.get(col, 0) for col in model.feature_names_in_
                    ]

                    X = pd.DataFrame([feature_values], columns=model.feature_names_in_)

                    # prediksi
                    prob = model.predict_proba(X)[0]
                    classes = list(model.classes_)

                    prob_phish = prob[classes.index("phishing")]
                    prob_legit = prob[classes.index("legitimate")]

                    # vote tree
                    tree_votes = []
                    for tree in model.estimators_:
                          pred = tree.predict(X.values)[0]
                          tree_votes.append(str(pred))

                          phish_votes = tree_votes.count("1.0")
                          legit_votes = tree_votes.count("0.0")
                          total_trees = len(model.estimators_)
                          
                    print("\nrekap voting random forest:")
                    print("Total Tree :", total_trees)
                    print("Vote Phishing :", phish_votes)
                    print("Vote Legitimate :", legit_votes)

                    print("\nhasil prediksi:")
                    print("URL :", url)
                    print("Classes :", classes)
                    print("Raw Probability :", prob)
                    print("Probabilitas Phishing :", prob_phish)
                    print("Probabilitas Legitimate :", prob_legit)

                    # hasil
                    if prob_phish > prob_legit:
                        status = "PHISHING"
                        confidence = prob_phish * 100
                    else:
                        status = "LEGITIMATE"
                        confidence = prob_legit * 100

                    print("\nhasil prediksi:")
                    for col in model.feature_names_in_:
                        print(f"{col} : {feats.get(col, 0)}")

                    result = {
                        "status": status,
                        "confidence": round(confidence, 2),
                        "phish": round(prob_phish, 4),
                        "legit": round(prob_legit, 4)
                    }

                except Exception as e:
                    result = {"error": f"Terjadi error: {str(e)}"}

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)