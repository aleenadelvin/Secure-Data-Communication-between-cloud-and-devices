#import Tkinter,filedialog
#from Tkinter import *
import tkinter
from tkinter import filedialog
from tkinter import *
import sys
import os
import des_encrypt_decrypt
from steganography import Steganography
from cloud_upload import upload_to_aws , load_shuffle_data , download_from_aws
from random import randint


master = ""
ment = ""


class MyFirstGUI:
    def __init__(self, master):
        self.master = master
        master.title("Custom hybrid cloud encrypt")
        master.geometry("290x200") 
        master.resizable(0, 0)


        self.entry = Entry(master)
        #self.entry.pack()
        self.entry.place(x=100,y= 105)

       
        
        self.label = Label(master, text="Hybrid cloud encryption",font=("Helvetica", 12),)
        #self.label.pack()
        self.label.place(x=43,y= 10)


        self.label1 = Label(master, text="KEY:",font=("Helvetica", 10),)
        #self.label.pack()
        self.label1.place(x=30,y= 105)

        self.greet_button = Button(master, text="Encrypt", command=self.encrypt)
        #self.greet_button.pack()
        self.greet_button.place(x=30,y= 135)

        self.greet_button = Button(master, text="Decrypt", command=self.decrypt)
        #self.greet_button.pack()
        self.greet_button.place(x=104,y= 135)

        self.greet_button = Button(master, text="Get file", command=self.about)
        #self.greet_button.pack()

        self.greet_button.place(x=180,y= 135)

        self.greet_button = Button(master, text="List cloud data", command=self.listed)
        self.greet_button.place(x=30,y= 60)




    def encrypt(self):
        entry= self.entry.get()
        print (entry)
        k = des_encrypt_decrypt.triple_des(entry,             \
                            des_encrypt_decrypt.code_block_chain ,\
                            "\0\0\0\0\0\0\0\0",     \
                            pad=None, padmode=des_encrypt_decrypt.PKCS5_P)

        print("Choosing file!")
        filez = filedialog.askopenfilenames(parent=root,title='Choose a file')

        #try:
        lis = list(filez)
        print (lis)
        list_filename = lis[0].split('/')
        print (list_filename)
        file_up = list_filename[len(list_filename)-1]
        print (file_up)
            

        with open(lis[0], 'r') as myfile:
            data1=myfile.read()
            #print (data1)
        
            
        encStr = k.encrypt(data1)

            #encStr = crypt.encryptStringENC(data1)
            #print(encStr)
        file1 = open('log/secret.txt','wb')
        file1.write(encStr)
        file1.close()
        uploaded = upload_to_aws('log/secret.txt', 'encry3desanuja', file_up)

            #file1 = drive.CreateFile({'title': file_up})
            #file1.SetContentString(encStr)
            #file1.Upload() # Files.insert()'''
        print("Choosing image file!")
        filez = filedialog.askopenfilenames(parent=root,title='Choose a image file')
        lis = list(filez)
        print (lis)
        self.stegano(entry,lis[0],'E')
        value = randint(0, 100000)
        uploaded = upload_to_aws('log/encry_image.jpg', 'encry3desanuja', str(value)+'.jpg')
        self.riffle_shuffle(file_up,str(value)+'.jpg')
        self.encryPop()
        #except:
            #self.Pop("Please choose text file for encryption")
            

    def decrypt(self):
        print("Choosing image file!")
        filez = filedialog.askopenfilenames(parent=root,title='Choose a image file')
        lis = list(filez)
        print (lis)
        entry = "nokey"
        key_data = self.stegano(entry,lis[0],'D')

        k = des_encrypt_decrypt.triple_des(key_data,             \
                            des_encrypt_decrypt.code_block_chain ,\
                            "\0\0\0\0\0\0\0\0",     \
                            pad=None, padmode=des_encrypt_decrypt.PKCS5_P)
        
        #try:
            #entry= self.entry.get()

            #data = "welcome to des encryption"
            #file7 = drive.CreateFile({'id': entry})
            #content = file7.GetContentString()
            #print content
        #file1 =open('secret.txt','w')
        #file1.write(content)
        #file1.close()
            
            
        print("Choosing file!")
        filez = filedialog.askopenfilenames(parent=root,title='Choose a file')
        root.tk.splitlist(filez)
        lis = list(filez)
        print (lis)

        with open(lis[0], 'rb') as myfile:
            data1=myfile.read()
            print (data1)
            
            dec_data = k.decrypt(data1)
            #d = crypt.decryptStringENC(data1)

            

        file =open('log/DATA.txt','wb')
        file.write(dec_data);
        file.close()
        print (dec_data)

        self.outCrypt()
        self.Pop(self,'v1.0 developed by anuja')
            

        #except:
            #self.Pop("No internet connection or Please provide file identifier")
            

    def stegano(self,key,path,encode_decode):
        output_path = "log/encry_image.jpg"
        if (encode_decode == 'E'):
            Steganography.encode(path, output_path, key)
            print("Steganography DONE\n")
        else:
            secrete_text = Steganography.decode(output_path)
            print (secrete_text)  
            return secrete_text
             #headfirst java, c ,cpp
        

    def listed(self):
        global master

        #cont=""

        #file_list = drive.ListFile({'q': "'root' in parents"}).GetList()
        #for file1 in file_list:
         #   cont+= "Filename: " +str(file1['title'])+"----->ID: " +str(file1['id'])+"\n"
            
        package_name = []
        version_key = []
        cont=""
        download_from_aws('riffle_shuffle.txt','log/riffle_shuffle.txt')
        package_name , version_key = load_shuffle_data()
        for i, j in zip(package_name, version_key ):
            cont+= str(i) + '->' + str(j) +"\n"
        popup = Tk()
        popup.wm_title("!")
        scrollbar = Scrollbar(popup)
        scrollbar.pack(side=RIGHT, fill=Y)

        text = Text(popup, wrap=WORD, yscrollcommand=scrollbar.set)
        text.insert(END,cont)
        text.pack()

        scrollbar.config(command=text.yview)
        
        
        #label = Label(popup, text=cont,font=("Helvetica", 12),)
        #label.pack()
        B1 = Button(popup, text="Okay", command = popup.destroy)
        B1.pack()
        popup.mainloop()



    def about(self):
        global master
        cont = ''' File downloaded'''
        entry= self.entry.get()
        print (entry)
        download_from_aws(entry,'log/'+entry)
        popup = Tk()
        popup.wm_title("!")
        label = Label(popup, text=cont,font=("Helvetica", 12),)
        label.pack()
        B1 = Button(popup, text="Okay", command = popup.destroy)
        B1.pack()
        popup.mainloop()
    
    def riffle_shuffle(self,file_name,random_name):
        file = open ('log/riffle_shuffle.txt','a')
        file.write(file_name + ':' +random_name+ '\n')
        file.close()
        upload_to_aws('log/riffle_shuffle.txt', 'encry3desanuja', 'riffle_shuffle.txt')
        #os.remove('riffle_shuffle.txt')

    def encryPop(self):
        global master
        cont = '''Encrypted and uploaded to cloud'''
        popup = Tk()
        popup.wm_title("!")
        label = Label(popup, text=cont,font=("Helvetica", 12),)
        label.pack()
        B1 = Button(popup, text="Okay", command = popup.destroy)
        B1.pack()
        popup.mainloop()




    def Pop(self,msg):
        global master
        popup = Tk()
        popup.wm_title("!")
    
        
        label = Label(popup, text=msg,font=("Helvetica", 12),)
        label.pack()
        B1 = Button(popup, text="Okay", command = popup.destroy)
        B1.pack()
        popup.mainloop()

    def outCrypt(self):
        global master

        file1 =open('log/DATA.txt','rb')
        cont = file1.read()
        file1.close()


        popup = Tk()
        popup.wm_title("!")
        scrollbar = Scrollbar(popup)
        scrollbar.pack(side=RIGHT, fill=Y)

        text = Text(popup, wrap=WORD, yscrollcommand=scrollbar.set)
        text.insert(END,cont)
        text.pack()

        scrollbar.config(command=text.yview)
        
        
        #label = Label(popup, text=cont,font=("Helvetica", 12),)
        #label.pack()
        B1 = Button(popup, text="Okay", command = popup.destroy)
        B1.pack()
        popup.mainloop()
 




root = Tk()
my_gui = MyFirstGUI(root)
root.mainloop()

