import sys
import traceback
from time import process_time_ns
import Flask
import re


from transformers import AutoTokenizer, TFAutoModelForSequenceClassification
from flask import Flask, request, jsonify
from classification_model import VulnerabilityDetectionSystem

import logging
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


MODEL_SAVE_DIR = "C:/Users/Alexandra/Documents/GitHub/LicentaFinala/AI/saved_models/vulnerability_system3sources2"
app = Flask(__name__)
system = VulnerabilityDetectionSystem.load(MODEL_SAVE_DIR)

@app.route('/classify', methods=['POST'])
def classify():
    print("classify")
    app.logger.info("Classification request received")

    try:

        app.logger.debug(f"Raw request data: {request.data}")
        data = request.get_json()
        app.logger.debug(f"Parsed JSON: {data}")

        if not data or 'text' not in data:
            app.logger.error("Missing 'text' field in request")
            return jsonify({"error": "Missing 'text' field"}), 400

        raw_code = data['text']
        app.logger.info(f"Processing code (length: {len(raw_code)})")

        app.logger.debug(f"Code sample: {raw_code[:200]}...")

        predictions, confidences = system.predict([raw_code])
        app.logger.info(f"Prediction results - labels: {predictions}, confidences: {confidences}")

        return jsonify({
            "label": "Vulnerable" if predictions[0][0] == 1 else "Not Vulnerable",
            "confidence":  round( float(confidences[0][0]) * 100 if predictions[0][0] == 1 else (1 - float(confidences[0][0])) * 100, 5)
        })

    except Exception as e:
        app.logger.error("Classification failed", exc_info=True)
        return jsonify({
            "error": str(e),
            "type": type(e).__name__,
            "traceback": traceback.format_exc()
        }), 500


@app.route("/test", methods=["GET"])
def test_model_loading():
    print("Received POST /TEST")  # Should show immediately
    try:
        system = VulnerabilityDetectionSystem.load(MODEL_SAVE_DIR)
        return jsonify({"status": "Model loaded successfully"})
    except Exception as e:
        import traceback
        return jsonify({
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
