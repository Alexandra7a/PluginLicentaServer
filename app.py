import sys
import traceback
from flask import Flask, request, jsonify
from classification_model import VulnerabilityDetectionSystem
import logging


logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
MODEL_SAVE_DIR = "C:/Users/Alexandra/Documents/GitHub/LicentaFinala/AI/saved_models/vulnerability_system3sources"
app = Flask(__name__)
system = VulnerabilityDetectionSystem.load(MODEL_SAVE_DIR)

@app.route('/classify', methods=['POST'])
def classify():
    app.logger.info("Classification request received")
    try:
        data = request.get_json()

        if not data or 'text' not in data:
            return jsonify({"error": "Missing 'text' field"}), 400

        raw_code = data['text']
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

if __name__ == '__main__':
    app.run(debug=True)
