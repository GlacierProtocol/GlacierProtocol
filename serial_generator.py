#!/usr/bin/env python
import os
import glob
import strgen
import sys
from bip38 import *
from bitcoin import *
from qrcode import *
from PIL import Image
from PIL import ImageFont
from PIL import ImageDraw
from fpdf import FPDF
from PIL import Image

batch_num = raw_input("Please enter a batch ID:")
serialqty = input("How many products would you like to mark?:")
wallets = []
serials = strgen.StringGenerator("[\d\w]{7}").render_list(serialqty,unique=True)

for serial in serials:
    serial = serial.encode('utf-8')
    pasw = serial
    priv = random_key()
    wif = encode_privkey(priv, 'wif')
    addr = privtoaddr(wif)
    bip = bip38_encrypt(wif,pasw)

    #image...
    img = Image.open("background.jpg") #around 1000 x 500
    img_w, img_h = img.size

  #QR image for addr
    qr = QRCode(box_size=4, border=3, error_correction=ERROR_CORRECT_Q) 
    qr.add_data(addr)
    im = qr.make_image()
    im_w, im_h = im.size

    #QR image for key
    qr2 = QRCode(box_size=1, border=3, error_correction=ERROR_CORRECT_M) 
    qr2.add_data(bip)
    im2 = qr2.make_image()
    im2_w, im2_h = im2.size

    #draw QRs
    offs = (img_w - im_w - im2_w) / 4
    img.paste(im2, (im_w+(600),(img_h-im2_h)/8) )    
    
    
    #draw labels
    draw = ImageDraw.Draw(img) 
    font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc",12)
    fcolor =  (0,0,0)
    draw.text((15, 17), 'SERIAL:  ' + serial, fcolor, font)
    draw.text((200, 17), 'BIP38 KEY:  ' + bip, fcolor, font)
    if not os.path.exists(batch_num): 
        os.mkdir(batch_num)
    img.save(batch_num+'/'+addr+'.jpg', "JPEG")
    
wallets = [Image.open(item) for i in [glob.glob(batch_num+'/*.%s' % ext) for ext in ["jpg","gif","png","tga"]] for item in i]
widths, heights = zip(*(i.size for i in wallets))



total_width = sum(widths)
max_height = max(heights)

new_im = Image.new('RGB', (total_width, max_height))

x_offset = 0
for im in wallets:
  new_im.paste(im, (x_offset,0))
  x_offset += im.size[0]

new_im.save(batch_num+"/"+batch_num+'.jpg')
