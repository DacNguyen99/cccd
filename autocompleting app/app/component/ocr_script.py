import os
import sys
import logging
from paddleocr import PaddleOCR
from PIL import Image
import json

# Suppress DEBUG and WARNING logs from PaddleOCR
logging.getLogger('ppocr').setLevel(logging.ERROR)

def process_ocr_result(text):
    text = text.replace('<', '')
    data = {}

    if text.startswith('ID'):
        data["id"] = text[:5]
        data["cccdnumber1"] = text[5:14]
        data["checksum1"] = text[14] if len(text) > 14 else ''
    elif text.startswith('0'):
        birth = f"{text[:2]}{text[2:4]}{text[4:6]}"
        expire = f"{text[8:10]}{text[10:12]}{text[12:14]}"
        data["birth"] = birth
        data["checksum3"] = text[6] if len(text) > 6 else ''
        data["expire"] = expire
        data["checksum4"] = text[14] if len(text) > 14 else ''

    return data
    
def process_images(img_path):
    output_dir = 'icao'
    os.makedirs(output_dir, exist_ok=True)
    
    ocr_model = PaddleOCR(lang='en')
    result = ocr_model.ocr(img_path)
    
    result_data = []
    
    for res in result:
        for line in res:
            data = process_ocr_result(line[1][0])
            result_data.append(data)
    
    # Save JSON
    with open(os.path.join(output_dir, 'result.json'), 'w', encoding='utf-8') as json_file:
        json.dump(result_data, json_file, ensure_ascii=False, indent=4)
    
    return result_data


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)
    img_path = sys.argv[1]
    process_images(img_path)
