from PIL import Image
from PyPDF2 import PdfFileWriter, PdfFileReader

with open("txt_to_append.txt", 'a') as f:
    f.write(" Teste feito.")

imgPath = "img_to_flip.png"
image = Image.open(imgPath)
flipped = image.transpose(Image.FLIP_LEFT_RIGHT)
flipped.save(imgPath)

output = PdfFileWriter()
with open("pdf_to_addpage.pdf", 'rb+') as f:
    pdf = PdfFileReader(f)
    f.seek(0)
    output.addPage(pdf.getPage(0))
    output.addPage(pdf.getPage(0))
    output.write(f)
    f.truncate()
