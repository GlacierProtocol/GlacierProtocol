import numpy as np
from PIL import Image
# need to put the .jpg files in one by one.  Want to find a way to get everthing in a spacific directory.
images_list = ['/Users/christophergliatas/projects/counterfeit_stop/1/1HrvvBZGg5hGDx3rKDbPHyU2pzH2u1nQcK.jpg',
    '/Users/christophergliatas/projects/counterfeit_stop/1/1HKGbK6dTMuaTxmDMzHPWJvctCoyB1mJ3G.jpg',
    '/Users/christophergliatas/projects/counterfeit_stop/1/1DZLhuHQ95SobrHQmyfyUM4Dbc4BGPJobb.jpg',
    '/Users/christophergliatas/projects/counterfeit_stop/1/1HLmkRSdG1Ewf79HsNj9Mt2dnQ6qi9CNWN.jpg',
    '/Users/christophergliatas/projects/counterfeit_stop/1/1KZfd6rH62uycCMQuXbnjUzSMqB27SYVFN.jpg',
    '/Users/christophergliatas/projects/counterfeit_stop/1/1NXv5re2pm6yuv6fv8AwomCFUqfbkKvJF7.jpg',
    '/Users/christophergliatas/projects/counterfeit_stop/1/1Q7oHd7JjWZgkJua1f2P9QKdXFB1VZTbcY.jpg',
    '/Users/christophergliatas/projects/counterfeit_stop/1/16oBXr6ETrsT41M4D8PmwPds8azY71cgL3.jpg',
    '/Users/christophergliatas/projects/counterfeit_stop/1/18UA3JQ7gvY18M5F6iz1cN4webiJmSXk79.jpg',
    '/Users/christophergliatas/projects/counterfeit_stop/1/121zR3yzQaP2VvGvvDRAXD2RyAuBG17MkX.jpg',]
imgs = [ Image.open(i) for i in images_list ]
# Take the size of the smallest .jpg
min_img_shape = sorted( [(np.sum(i.size), i.size ) for i in imgs])[0][1]
# Resizes all .jpg files to the size of the smallest .jpg
img_merge = np.vstack( (np.asarray( i.resize(min_img_shape,Image.ANTIALIAS) ) for i in imgs ) )
# Merges all .jpg files into an array.
img_merge = Image.fromarray( img_merge)
# Saves the new array "filename".jpg
img_merge.save( 'vert_compiled.jpg' )