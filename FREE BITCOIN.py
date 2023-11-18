#!/usr/bin/env python
# coding: utf-8

# In[3]:


import tkinter as tk
import hashlib
import codecs
import base58
import webbrowser
import pyperclip
from Crypto.Hash import RIPEMD160


WIF=" "
Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 # The proven prime
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
Acurve = 0; Bcurve = 7 # These two defines the elliptic curve. y^2 = x^3 + Acurve * x + Bcurve
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
GPoint = (Gx,Gy) # This is our generator point. Trillions of dif ones possible

def copiar_al_portapapeles():
    texto = public_key_text.get("1.0", "end-1c")  # Obtiene el texto del widget Text
    pyperclip.copy(texto)  # Copia el texto al portapapeles
    
def copiar_al_portapapeles_2():
    # Obtiene el texto del widget Text
    pyperclip.copy(WIF)

def cambiar_cursor(event):
    blank_space.config(cursor="hand2")

def restaurar_cursor(event):
    blank_space.config(cursor="")

def generate_on_enter(event):
    generate_address()

def modinv(a,n=Pcurve): #Extended Euclidean Algorithm/'division' in elliptic curves
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        ratio = int(high/low)
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECadd(a,b): # Not true addition, invented for EC. Could have been called anything.
    LamAdd = ((b[1]-a[1]) * modinv(b[0]-a[0],Pcurve)) % Pcurve
    x = (LamAdd*LamAdd-a[0]-b[0]) % Pcurve
    y = (LamAdd*(a[0]-x)-a[1]) % Pcurve
    return (x,y)

def ECdouble(a): # This is called point doubling, also invented for EC.
    Lam = ((3*a[0]*a[0]+Acurve) * modinv((2*a[1]),Pcurve)) % Pcurve
    x = (Lam*Lam-2*a[0]) % Pcurve
    y = (Lam*(a[0]-x)-a[1]) % Pcurve
    return (x,y)

def EccMultiply(GenPoint,ScalarHex): #Double & add. Not true multiplication
    if ScalarHex == 0 or ScalarHex >= N: raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(ScalarHex))[2:]
    Q=GenPoint
    for i in range (1, len(ScalarBin)): # This is invented EC multiplication.
        Q=ECdouble(Q); # print "DUB", Q[0]; print
        if ScalarBin[i] == "1":
            Q=ECadd(Q,GenPoint); # print "ADD", Q[0]; print
    return (Q)
    
def hextobyte (content):
    return codecs.decode(content.encode("utf-8"), "hex")

def hashhex(algorithm, content):
    if algorithm == 'ripemd160':
        hash = RIPEMD160.new()
    else:
        hash = hashlib.new(algorithm)
    
    hash.update(hextobyte(content))
    return hash.hexdigest()


def base58_a(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add ‘1’ for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string
    
def toggle_private_key():
    # Verifica si el Checkbutton está seleccionado
    if show_hide_checkbox_var.get():
        private_key_text.config(state="normal")
        # Clear existing text in Text widgets
        private_key_text.delete('1.0', tk.END)
        # Insert new text in Text widgets
        secrets="*"*len(WIF)
        private_key_text.insert(tk.END, secrets)
        # Configura una etiqueta de estilo para centrar el texto
        private_key_text.tag_configure("center", justify="center")
        # Aplica la etiqueta de estilo al rango de texto
        private_key_text.tag_add("center", "1.0", "end")
        private_key_text.config(state="disabled")
    else:
        private_key_text.config(state="normal")
        # Clear existing text in Text widgets
        private_key_text.delete('1.0', tk.END)
        # Insert new text in Text widgets
        private_key_text.insert(tk.END, WIF)
        # Configura una etiqueta de estilo para centrar el texto
        private_key_text.tag_configure("center", justify="center")
        # Aplica la etiqueta de estilo al rango de texto
        private_key_text.tag_add("center", "1.0", "end")
        private_key_text.config(state="disabled")

############################################################

    #text = input ("what text you wanna hash? ")
    
#abrir enlace


def abrir_enlace(event):
    webbrowser.open("https://www.blockchain.com/en/explorer")
    
    
def generate_address():
    
    text = text_entry.get()
    
    #now we need to process a hash of the text variable
    try:
        hashed_output = hashlib.sha256(text.encode('ascii')).hexdigest()
    except:
        hashed_output =hashlib.sha256("".encode('ascii')).hexdigest()

    #Individual Transaction/Personal Information

    hasher = int(hashed_output, 16)
    privKey = hasher #replace with any private key


    #print; print ("******* Public Key Generation *********"); print
    PublicKey = EccMultiply(GPoint,privKey)
    #print ("the private key:"); print (privKey); print
    #print ("the uncompressed public key (not address):"); print (PublicKey); print;
    #print ("the uncompressed public key (HEX):"); 
    publicKeyHex = ("04" + "{:064x}".format(PublicKey[0]) + "{:064x}".format(PublicKey[1]))
    #print ("the official Public Key - compressed:"); 
    if PublicKey[1] % 2 == 1: 
        # If the Y value for the Public Key is odd.
        public_key="03"+str(hex(PublicKey[0])[2:]).zfill(64)
    else: # Or else, if the Y value is even.
        public_key="02"+str(hex(PublicKey[0])[2:]).zfill(64)


    output = hashhex ("sha256", publicKeyHex)   
    output = hashhex ("ripemd160", output)
    output = "00" + output

    checksuma = hashhex ('sha256', output)
    checksuma = hashhex ('sha256', checksuma)
    checksuma = checksuma[0:8]

    adressess= output + checksuma
    
    
    adressess=str(base58.b58encode(hextobyte(adressess)))
    address_bitcoin=adressess[2:len(adressess) - 1]
    PK0 = hashed_output
    PK1 = '80'+ PK0
    PK2 = hashlib.sha256(codecs.decode(PK1, 'hex'))
    PK3 = hashlib.sha256(PK2.digest())
    checksum = codecs.encode(PK3.digest(), 'hex')[0:8]
    PK4 = PK1 + str(checksum)[2:10]  #I know it looks wierd

    # Define base58
    global WIF
    WIF = base58_a(PK4)
    
    
    # Clear existing text in Text widgets
    public_key_text.config(state="normal")
    # Clear existing text in Text widgets
    public_key_text.delete('1.0', tk.END)
    # Insert new text in Text widgets
    public_key_text.insert(tk.END, address_bitcoin)
    public_key_text.config(state="disabled")
    # Configura una etiqueta de estilo para centrar el texto
    public_key_text.tag_configure("center", justify="center")
    # Aplica la etiqueta de estilo al rango de texto
    public_key_text.tag_add("center", "1.0", "end")

    
    if show_hide_checkbox_var.get():
        private_key_text.config(state="normal")
        # Clear existing text in Text widgets
        private_key_text.delete('1.0', tk.END)
        # Insert new text in Text widgets
        secrets="*"*len(WIF)
        private_key_text.insert(tk.END, secrets)
        # Configura una etiqueta de estilo para centrar el texto
        private_key_text.tag_configure("center", justify="center")
        # Aplica la etiqueta de estilo al rango de texto
        private_key_text.tag_add("center", "1.0", "end")
        private_key_text.config(state="disabled")
        
        
    else:
        private_key_text.config(state="normal")
        # Clear existing text in Text widgets
        private_key_text.delete('1.0', tk.END)
        # Insert new text in Text widgets
        private_key_text.insert(tk.END, WIF)
        # Configura una etiqueta de estilo para centrar el texto
        private_key_text.tag_configure("center", justify="center")
        # Aplica la etiqueta de estilo al rango de texto
        private_key_text.tag_add("center", "1.0", "end")
        private_key_text.config(state="disabled")

root = tk.Tk()
root.title("Bitcoin Wallet Generator")

root.geometry("500x380")


# Crear y posicionar widgets en la ventana
text_label = tk.Label(root, text="Insert Text:", font=("Helvetica", 12))
text_label.grid(row=0, column=0, columnspan=2, pady=10)

text_entry = tk.Entry(root, width=50, font=("Helvetica", 12), justify="center")
text_entry.grid(row=1, column=0, columnspan=2, pady=1)

generate_button = tk.Button(root, text="GENERATE WALLET",  width = 15, height = 2, command=generate_address, fg='white', bg='black')
generate_button.grid(row=2, column=0, columnspan=2, pady=10)

public_key_label = tk.Label(root, text="Bitcoin Address:", font=("Helvetica", 12))
public_key_label.grid(row=3, column=0, columnspan=2, pady=10, sticky="s")

# Crear un botón para copiar al portapapeles
boton_copiar = tk.Button(root, text="copy", width = 4, height = 1, command=copiar_al_portapapeles, fg='black', bg='white', font=("Helvetica", 8))
boton_copiar.grid(row=3, column=1, columnspan=2, pady=2)

# Create Text widgets for displaying public and private keys
public_key_text = tk.Text(root, height=1, width=55, wrap=tk.WORD, bg='lavender', font=("Helvetica"))
public_key_text.grid(row=4, column=0, columnspan=2, pady=10)
public_key_text.tag_configure("center", justify="center")

blank_space = tk.Label(root, text="https://www.blockchain.com/en/explorer",fg="blue", font=("Helvetica", 10))
blank_space.grid(row=5, column=0,columnspan=3, pady=0)

private_key_label = tk.Label(root, text="Private Key (WIF):", font=("Helvetica", 12))
private_key_label.grid(row=6, column=0, pady=10)

# Crear un botón para copiar al portapapeles
boton_copiar = tk.Button(root, text="copy", width = 4, height = 1, command=copiar_al_portapapeles_2, fg='black', bg='white', font=("Helvetica", 8))
boton_copiar.grid(row=6, column=1, pady=2, sticky="W")

show_hide_checkbox_var = tk.BooleanVar(value=True)
show_hide_checkbox = tk.Checkbutton(root, text="Hide/Show", variable=show_hide_checkbox_var, command=toggle_private_key, font=("Helvetica", 11))
show_hide_checkbox.grid(row=6, column=1, pady=10)

private_key_text = tk.Text(root, height=1, width=55, wrap=tk.WORD, bg='lavender', font=("Helvetica", 10))
private_key_text.grid(row=7, column=0, columnspan=2, pady=10, sticky="s")

blank_space_2 = tk.Label(root, text="")
blank_space_2.grid(row=8, column=0,columnspan=3, pady=0)

donate_me_1 = tk.Label(root, text="Donate me =)", font=("Helvetica", 8))
donate_me_1.grid(row=9, column=0, pady=0, sticky="w")

donate_me = tk.Text(root, height=1, width=45, wrap=tk.WORD, bg='alice blue', font=("Helvetica", 8))
donate_me.grid(row=9, column=1, pady=10, sticky="e")
donate_me.insert(tk.END, "bc1qmvx9mgsy0wn45s86nx2wsxjcjr29e57mjdyns3")
donate_me.config(state="disabled")

#ejecucion al presionar enter
text_entry.bind("<Return>", generate_on_enter)

# Asocia la función abrir_enlace al evento de clic
blank_space.bind("<Button-1>", abrir_enlace)

# Cambia el cursor cuando el ratón entra en el área del widget
blank_space.bind("<Enter>", cambiar_cursor)

# Restaura el cursor cuando el ratón sale del área del widget
blank_space.bind("<Leave>", restaurar_cursor)
# ... (rest of your code remains unchanged)

# Iniciar el bucle de la GUI
root.mainloop()


# In[4]:





# In[ ]:




