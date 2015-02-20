import hashlib
import binascii
import random
import time
import ctypes
import hmac
import os
import getpass
from math import ceil
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from PIL import Image
rng = random.SystemRandom()
mask_remove_bit = 0b11111110
bit_3_mask = 0b111


class HMACMismatch(Exception):
	pass
	
class FileWillNotFit(Exception):
	pass

def init_key_generation(keylengthbits):
	if keylengthbits < 8:
		keylengthbits = 8
	elif keylengthbits % 8 != 0:
		keylengthbits += ( 8 - keylengthbits % 8)
	key = []
	iters = keylengthbits // 8
	for i in range(0,iters):
		key.append(format(rng.randint(0,255), '02x'))
	return "".join(key)
	
def create_random_key(length):
	rng = random.SystemRandom()
	vtr = bytearray()
	for i in range(0,length):
		vtr.append(rng.randint(0,255))
	return vtr
	
def do_xor_on_hex(str1,str2):
	l1 = len(str1)
	if l1 != len(str2) or l1 % 2 != 0:
		print("ERROR!")
		return "Error"
	xor = []
	for i in range(0,l1,2):
		xor.append(format(int(str1[i:i+2],16)^int(str2[i:i+2],16),"02x"))
	return "".join(xor)
	
def do_xor_on_bytes(bs1,bs2):
	l1 = len(bs1)
	if l1 != len(bs2):
		print("ERROR!")
		return "Error"
	xor = bytearray()
	for i in range(0,l1):
		xor.append(bs1[i] ^ bs2[i])
	return xor

def hex_transpose(hexstr):
	v1 = 0
	newhex = []
	hexlen = len(hexstr)
	for i in range(0,hexlen,2):
		newhex.append(hexstr[i+1] + hexstr[i])
	newhex2 = newhex[(hexlen//4):] + newhex[0:(hexlen//4)]
	#print(newhex2)
	return "".join(newhex2)
	
def byte_transpose(binarr):
	binarrlen = len(binarr)
	newbin = bytearray()
	for i in range(0,binarrlen,2):
		newbin.append(binarr[i+1])
		newbin.append(binarr[i])
	newbin2 = newbin[(binarrlen//2):] + newbin[:(binarrlen//2)]
	return newbin2

def generate_header_contents(f_len, password, ver, key_amount, pbkdf2_iterations):
	header = []
	if key_amount > 65535 or len(ver) != 2 or pbkdf2_iterations > 65535:
		return "F"
	#print('key amount:',key_amount)
	key_amount_str = format(key_amount, '02x')
	pbkdf2_real_iters = pbkdf2_iterations * 1000
	pbkdf2_str = format(pbkdf2_iterations, '02x')
	while len(key_amount_str) < 4:
		key_amount_str = "0" + key_amount_str
	while len(pbkdf2_str) < 4:
		pbkdf2_str = "0" + pbkdf2_str
	header.append(key_amount_str)
	header.append(pbkdf2_str)
	#print('pbkdf2 iters:',pbkdf2_real_iters)
	#print(header)
	final_key_split = []
	for i in range(0,key_amount):
		cs = init_key_generation(512)
		#print('salt:',cs)
		ck = init_key_generation(512)
		final_key_split.append(ck)
		#print(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), 10000))
		k_xor_mask = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), pbkdf2_real_iters)))
		ciphered_key = do_xor_on_hex(k_xor_mask,ck)
		header.append(cs)
		header.append(ciphered_key)
	#print('version:',ver)
	#print('length:',f_len)
	header.append(ver)
	header.append(f_len)
	hmac_salt = header[2]
	#print(hmac_salt)
	k_pbkdf_hmac = hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(hmac_salt), pbkdf2_real_iters*4)
	n_head = "".join(header)
	#print(n_head)
	hmac_val = hmac.new(k_pbkdf_hmac, n_head.encode(), hashlib.sha512).hexdigest()
	n_head_2 = []
	n_head_2.append(n_head)
	n_head_2.append(hmac_val)
	#print('key:', "".join(final_key_split))
	return "".join(n_head_2), "".join(final_key_split)
	
	
def read_header_contents(header_str, password):
	key_amount = int(header_str[0:4],16)
	pbkdf2_iterations = int(header_str[4:8],16)
	pbkdf2_real_iters = pbkdf2_iterations * 1000
	#print('key amount:',key_amount)
	#print('pbkdf2 iters:',pbkdf2_real_iters)
	hmac_in_hdr = header_str[-128:]
	#print(header_str[4:132])
	k_pbkdf_hmac = hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(header_str[8:136]), pbkdf2_real_iters*4)
	hmac_val = hmac.new(k_pbkdf_hmac, header_str[:-128].encode(), hashlib.sha512).hexdigest()
	if hmac_in_hdr == hmac_val:
		hmac_validated = True
	else:
		hmac_validated = False
	#print('read hmac:',hmac_in_hdr)
	#print('calculated hmac:', hmac_val)
	final_key = []
	for i in range(0,key_amount):
		cs = header_str[(i*256)+8:(i*256)+136]
		#print('salt:',cs)
		ck = header_str[(i*256)+136:(i*256)+264]
		#print(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), 10000))
		k_xor_mask = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password.encode(), bytes.fromhex(cs), pbkdf2_real_iters)))
		deciphered_key = do_xor_on_hex(k_xor_mask,ck)
		final_key.append(deciphered_key)
	ver = header_str[(key_amount*256)+8:(key_amount*256)+10]
	length = header_str[(key_amount*256)+10:-128]
	#print('version:',ver)
	#print('length:',length)
	fk = "".join(final_key)
	#print('key:', fk)
	return fk, ver, length, hmac_validated
	
	
# class sha512_nfb(object):
	# def __init__(self, init_key):
		# self.current_state = bytearray(hashlib.sha512(bytes.fromhex(init_key)).digest())
	# def get_output(self):
		# initk = self.current_state
		# self.current_state = bytearray(hashlib.sha512(initk).digest())
		# return bytearray(hashlib.sha512(byte_transpose(initk)).digest()) 
		
def int_to_big_endian(intg, pad_to=16):
	m_big = 0b11111111
	big_endian_int = bytearray()
	times_to_iterate = ceil(len(bin(intg)[2:])/8)
	for i in range(0,times_to_iterate):
		big_endian_int.append((intg >> (i*8)) & m_big)
	while len(big_endian_int) < pad_to:
		big_endian_int.append(0)
	big_endian_int.reverse()
	return big_endian_int

def big_endian_to_int(big_endian_barr):
	big_endian = big_endian_barr
	cur_num = 0
	for i in range(0,len(big_endian)):
		cur_num = (cur_num << 8) | big_endian[i]
	return cur_num
	
def bytes_to_3_bit_chunks(bytearr):
	des_int = big_endian_to_int(bytearr)
	i_list = []
	for i in range(0,8):
		i_list.append(des_int & bit_3_mask)
		des_int >>= 3
	i_list.reverse()
	return i_list

def bit_3_chunks_to_bytes(chunks):
	int_des = 0
	for i in range(0,8):
		int_des <<= 3
		int_des |= chunks[i]
	return int_to_big_endian(int_des, pad_to=3)

def create_key_xor_mask(salt,password):
	#USE 2M ITERS!
	xor_mask = hashlib.pbkdf2_hmac('sha512',password.encode(),salt,4000000)
	return xor_mask

def input_int_until_list_or_default(list_desired, default_val):
	is_done = False
	while is_done == False:
		try:
			tv = int(input())
			if tv in list_desired:
				is_done = True
			else:
				print('Incorrect Value')
		except ValueError:
			tv = default_val
			is_done = True
	return tv
	
def input_file_until_file_found():
	is_done = False
	while is_done == False:
		tv = input()
		try:
			f = open(tv,'r')
			is_done = True
		except FileNotFoundError:
			print('File not found')
	return tv

def input_password_until_match():
	pass_ok = False
	while pass_ok == False:
		passwn = getpass.getpass('Password: ')
		passwn_check = getpass.getpass('Confirm password: ')
		if passwn == passwn_check:
			pass_ok = True
		else:
			print("Passwords don't match, please retry.")
	return passwn

class sha512_efb(object):
	def __init__(self, init_key):
		self.current_key = bytearray.fromhex(init_key)
		self.current_feedback = bytearray(hashlib.sha512(self.current_key).digest())
	def get_bytes_to_xor(self):
		self.current_key = self.current_key[-1:]+self.current_key[:-1]
		self.current_thing_to_hash = self.current_feedback+self.current_key
		self.current_feedback = bytearray(hashlib.sha512(self.current_thing_to_hash).digest())
		self.current_output_bytes = bytearray(hashlib.sha512(byte_transpose(self.current_thing_to_hash)).digest())
		return self.current_output_bytes

class sha512_efb_pfb(object):
	def __init__(self, init_key):
		self.current_key = bytearray.fromhex(init_key)
		self.current_feedback = bytearray(hashlib.sha512(self.current_key).digest())
	def get_bytes_to_xor(self,ptxthash):
		self.current_key = self.current_key[-1:]+self.current_key[:-1]
		self.current_thing_to_hash = self.current_feedback+ptxthash+self.current_key
		self.current_feedback = bytearray(hashlib.sha512(self.current_thing_to_hash).digest())
		self.current_output_bytes = bytearray(hashlib.sha512(byte_transpose(self.current_thing_to_hash)).digest())
		return self.current_output_bytes
		
class aes256_ede3_ctr(object):
		#key must be 1024 bit
	def __init__(self,init_key,mode="HEX"):
		if mode == "HEX":
			bytes_init_key = bytearray.fromhex(init_key)
		elif mode == "BYTES":
			bytes_init_key = bytearray(init_key)
		k1 = bytes_init_key[:32]
		k2 = bytes_init_key[32:64]
		k3 = bytes_init_key[64:96]
		k4 = bytes_init_key[96:128]
		aes_first = hashlib.sha256(k1+k4).digest()
		aes_second = hashlib.sha256(k2+k4).digest()
		aes_third = hashlib.sha256(k3+k4).digest()
		self.first_aes = AES.new(aes_first,AES.MODE_ECB)
		self.second_aes = AES.new(aes_second,AES.MODE_ECB)
		self.third_aes = AES.new(aes_third,AES.MODE_ECB)
		aes_iv = hashlib.md5(hashlib.sha256(hashlib.sha512(k1+k2+k3+k4).digest()).digest()).digest()
		#print('K1:',list(aes_first))
		#print('K2:',list(aes_second))
		#print('K3:',list(aes_third))
		#print('IV:',list(aes_iv))
		self.to_encrypt = big_endian_to_int(aes_iv)
	def get_bytes_to_xor(self):
		bytes_to_xor = bytearray()
		for i in range(0,4):
			cur_bytes_to_encrypt = bytes(int_to_big_endian(self.to_encrypt))
			self.to_encrypt = (self.to_encrypt + 1) % (2**128)
			#print(list(cur_bytes_to_encrypt))
			e1 = self.first_aes.encrypt(cur_bytes_to_encrypt)
			e2 = self.second_aes.decrypt(e1)
			e3 = self.third_aes.encrypt(e2)
			bytes_to_xor.extend(e3)
		return bytes_to_xor

def encrypt_file(filename,passtouse,ver,key_par, iter_k, mode="N", bytein=b"", hdrmode="PSK"):
	if mode == "N":
		try:
			ftoe = open(filename,'rb')
			ftoe_r = bytearray(ftoe.read())
			ftoe.close()
		except FileNotFoundError:
			print('File to encrypt not found')
			time.sleep(3)
			return "F"
	elif mode == "R":
		ftoe_r = bytearray(bytein)
	if hdrmode == "PSK":
		nfname = filename + '.header'
	elif hdrmode == "RSA":
		nfname = filename + '.rsaheader'
	try:
		header_presence_test = open(nfname,'rb')
		header_present = True
		header_presence_test.close()
	except FileNotFoundError:
		header_present = False
	if header_present == True:
		print('Header detected for file',filename,)
		print('If the file is already encrypted, overwriting it')
		print('WILL MAKE YOUR FILE UNRECOVERABLE, unless you have a')
		print('header file backup')
		x = input('Press Y to continue, other key to quit ')
		if (x != 'Y') and (x != 'y'):
			return "F"
		else:
			print('Header overwritten at your request!')
	ftoe_r_l = len(ftoe_r)
	#print("File length:",len(ftoe_r))
	timestopad = 64-(ftoe_r_l%64)
	for i in range(0,timestopad):
		ftoe_r.append(rng.randint(0,255))
	if hdrmode == "PSK":
		headercontent, tkey = generate_header_contents(format(ftoe_r_l, '02x'),passtouse,ver,key_par, iter_k)
		hfi = open(nfname,'w')
		hfi.write(headercontent)
		hfi.close()
		hfi = open(nfname,'r')
		tkey2,_,_, hmac_s= read_header_contents(hfi.read(),passtouse)
		hfi.close()
		if tkey == tkey2 and hmac_s == True:
			print('Header file created, written and validated')
		else:
			print('Header file malfunction')
			print('Data loss is possible if you continue')
			x = input('Press Y to continue, other key to quit ')
			if (x != 'Y') and (x != 'y'):
				return "F"
	elif hdrmode == "RSA":
		tkey = init_key_generation(1024)
		rsasimplehead = []
		rsasimplehead.append(tkey)
		rsasimplehead.append(ver)
		rsasimplehead.append(format(ftoe_r_l, '02x'))
		rsaheaderjoined = "".join(rsasimplehead)
		rsaheaderbytes = rsaheaderjoined.encode()
	tkey_bytes = bytes.fromhex(tkey)
	hmackey_enc = hashlib.sha512(bytearray(hashlib.sha512(tkey_bytes).digest())+bytearray(hashlib.sha256(tkey_bytes).digest())+bytearray(hashlib.md5(tkey_bytes).digest())).digest()
	print("HMAC key:",bytes.decode(binascii.hexlify(hmackey_enc)))
	f_hash = hmac.new(hmackey_enc,msg=ftoe_r,digestmod=hashlib.sha512).digest()
	print("HMAC:",bytes.decode(binascii.hexlify(f_hash)))
	ftoe_r.extend(f_hash)
	#print("File+Pad+HMAC length:",len(ftoe_r))
	ftoe_r_l = len(ftoe_r)
	enc_file = bytearray()
	timestoencrypt = ftoe_r_l // 64
	csc = max(1,int(timestoencrypt/100))
	time_st = time.time()
	if ver == '01':
		cipher_object = sha512_efb(tkey)
		for i in range(0,timestoencrypt):
			cc = ftoe_r[(i*64):(i*64)+64]
			cbx = cipher_object.get_bytes_to_xor()
			ce = do_xor_on_bytes(cc,cbx)
			enc_file.extend(ce)
			if i % csc == 0:
				print(str(int(round((i*100/timestoencrypt),0)))+'%')
	elif ver == '02':
		cipher_object = sha512_efb_pfb(tkey)
		iv = hashlib.sha512(bytes.fromhex(hex_transpose(tkey))).digest()
		cfb = iv
		for i in range(0,timestoencrypt):
			cc = ftoe_r[(i*64):(i*64)+64]
			cbx = cipher_object.get_bytes_to_xor(cfb)
			ce = do_xor_on_bytes(cc,cbx)
			cfb = hashlib.sha512(cc).digest()
			enc_file.extend(ce)
			if i % csc == 0:
				print(str(int(round((i*100/timestoencrypt),0)))+'%')
	elif ver == '03':
		cipher_object = aes256_ede3_ctr(tkey)
		for i in range(0,timestoencrypt):
			cc = ftoe_r[(i*64):(i*64)+64]
			cbx = cipher_object.get_bytes_to_xor()
			ce = do_xor_on_bytes(cc,cbx)
			enc_file.extend(ce)
			if i % csc == 0:
				print(str(int(round((i*100/timestoencrypt),0)))+'%')
	if mode == "N":
		fout = open(filename,'wb')
	elif mode == "R":
		fout = open(filename+".rsa","wb")
	fout.write(enc_file)
	fout.close()
	#print('wk:',tkey)
	#print('rk:',tkey2)
	print('time: ', str(time.time()-time_st))
	if hdrmode == "RSA":
		return rsaheaderbytes
	
def decrypt_file(filename,passtouse, test_decrypt, mode="N", hdrmode="PSK", hdrcontents=""):
	if mode == "N":
		try:
			efile = open(filename,'rb')
			efile_r = efile.read()
			efile.close()
		except FileNotFoundError:
			print('File to decrypt not found')
			time.sleep(3)
			return "Fail"
	elif mode == "R":
		try:
			efile = open(filename+".rsa",'rb')
			efile_r = efile.read()
			efile.close()
		except FileNotFoundError:
			print('File to decrypt not found')
			time.sleep(3)
			return "Fail"
	if hdrmode == "PSK":
		nfname = filename + '.header'
		try:
			hfile = open(nfname,'r')
			key,ver,hlen,val = read_header_contents(hfile.read(),passtouse)
			hfile.close()
		except FileNotFoundError:
			print("Header is missing!, if you don't have a")
			print("backup, then your file is LOST FOREVER")
			time.sleep(3)
			return "Fail"
		if val == False:
			print('Wrong password, or corrupted/tampered header')
			x = input('Press Y to continue, other key to quit ')
			if (x != 'Y') and (x != 'y'):
				return "Abort"
		else:
			print('Header read and OK')
	elif hdrmode == "RSA":
		nfname = filename + '.rsaheader'
		key = hdrcontents[:256]
		ver = hdrcontents[256:258]
		hlen = hdrcontents[258:]
	length = int(hlen,16)
	d_file = bytearray()
	timestodecrypt = len(efile_r) // 64
	csc = max(1,int(timestodecrypt/100))
	time_st = time.time()
	if ver == '01':
		cipher_object = sha512_efb(key)
		for i in range(0,timestodecrypt):
			ce = efile_r[(i*64):(i*64)+64]
			cbx = cipher_object.get_bytes_to_xor()
			cd = do_xor_on_bytes(ce,cbx)
			d_file.extend(cd)
			if i % csc == 0:
				print(str(int(round((i*100/timestodecrypt),0)))+'%')
	elif ver == '02':
		cipher_object = sha512_efb_pfb(key)
		iv = hashlib.sha512(bytes.fromhex(hex_transpose(key))).digest()
		cfb = iv
		for i in range(0,timestodecrypt):
			ce = efile_r[(i*64):(i*64)+64]
			cbx = cipher_object.get_bytes_to_xor(cfb)
			cd = do_xor_on_bytes(ce,cbx)
			cfb = hashlib.sha512(cd).digest()
			d_file.extend(cd)
			if i % csc == 0:
				print(str(int(round((i*100/timestodecrypt),0)))+'%')
	elif ver == '03':
		cipher_object = aes256_ede3_ctr(key)
		for i in range(0,timestodecrypt):
			ce = efile_r[(i*64):(i*64)+64]
			cbx = cipher_object.get_bytes_to_xor()
			cd = do_xor_on_bytes(ce,cbx)
			d_file.extend(cd)
			if i % csc == 0:
				print(str(int(round((i*100/timestodecrypt),0)))+'%')
	key_bytes = bytes.fromhex(key)
	hmackey_enc = hashlib.sha512(bytearray(hashlib.sha512(key_bytes).digest())+bytearray(hashlib.sha256(key_bytes).digest())+bytearray(hashlib.md5(key_bytes).digest())).digest()
	print("HMAC key:",bytes.decode(binascii.hexlify(hmackey_enc)))
	fcalc_hash = hmac.new(hmackey_enc,msg=d_file[:-64],digestmod=hashlib.sha512).digest()
	print("HMAC CALC:",bytes.decode(binascii.hexlify(fcalc_hash)))
	print("HMAC READ:",bytes.decode(binascii.hexlify(d_file[-64:])))
	print('time: ', str(time.time()-time_st))
	autoremove = True
	if test_decrypt == True:
		if fcalc_hash == d_file[-64:]:
			return "File integrity OK"
		else:
			return "File has been tampered or corrupted"
	if fcalc_hash == d_file[-64:]:
		print('File OK')
	else:
		autoremove = False
		print()
		#print('File has been tampered or corrupted')
		print("-------------WARNING----------------")
		print("------------------------------------")
		print("------------------------------------")
		print("HMAC MISMATCH, FILE COULD BE ALTERED")
		print("------------------------------------")
		print("------------------------------------")
		print("-------------WARNING----------------")
		print()
		x = input('Press Y to continue (header autodelete disabled), other key to quit')
		if (x != 'Y') and (x != 'y'):
			return "Abort"
	if mode == "N":
		outf = open(filename,'wb')
		outf.write(d_file[0:length])
		outf.close()
	elif mode == "R":
		return d_file[0:length]
	if autoremove == True:
		print('Header file autodeleted')
		os.remove(nfname)
		time.sleep(3)
		

def change_password(filename,password_old,password_new):
	nfname = filename + '.header'
	try:
		nf = open(nfname,'r')
		header_str = nf.read()
		nf.close()
	except FileNotFoundError:
		print("Header is missing!")
		time.sleep(3)
		return "F"
	key_amount = int(header_str[0:4],16)
	pbkdf2_iterations = int(header_str[4:8],16)
	pbkdf2_real_iters = pbkdf2_iterations * 1000
	hmac_in_hdr = header_str[-128:]
	k_pbkdf_hmac = hashlib.pbkdf2_hmac('sha512', password_old.encode(), bytes.fromhex(header_str[8:136]), pbkdf2_real_iters*4)
	hmac_val = hmac.new(k_pbkdf_hmac, header_str[:-128].encode(), hashlib.sha512).hexdigest()
	if hmac_in_hdr != hmac_val:
		hmac_validated = False
		print('Wrong password, or corrupted/tampered header')
		print('If you continue, damage could be irreversible')
		x = input('Press Y to continue, other key to quit ')
		if (x != 'Y') and (x != 'y'):
			return "F"
	else:
		hmac_validated = True
	print('read hmac:',hmac_in_hdr)
	print('calculated hmac:', hmac_val)
	new_header = []
	new_header.append(header_str[0:8])
	for i in range(0,key_amount):
		cs = header_str[(i*256)+8:(i*256)+136]
		ck = header_str[(i*256)+136:(i*256)+264]
		k_xor_mask_d = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password_old.encode(), bytes.fromhex(cs), pbkdf2_real_iters)))
		deciphered_key = do_xor_on_hex(k_xor_mask_d,ck)
		k_xor_mask_e = bytes.decode(binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password_new.encode(), bytes.fromhex(cs), pbkdf2_real_iters)))
		reciphered_key = do_xor_on_hex(k_xor_mask_e,deciphered_key)
		new_header.append(cs)
		new_header.append(reciphered_key)
	ver = header_str[(key_amount*256)+8:(key_amount*256)+10]
	length = header_str[(key_amount*256)+10:-128]
	new_header.append(ver)
	new_header.append(length)
	f_header = "".join(new_header)
	k_pbkdf_hmac_n = hashlib.pbkdf2_hmac('sha512', password_new.encode(), bytes.fromhex(f_header[8:136]), pbkdf2_real_iters*4)
	hmac_val_n = hmac.new(k_pbkdf_hmac_n, f_header.encode(), hashlib.sha512).hexdigest()
	nh = []
	nh.append(f_header)
	nh.append(hmac_val_n)
	finalr_head = "".join(nh)
	finalf = open(nfname,'w')
	finalf.write(finalr_head)
	finalf.close()
	print('Done!')
	
def force_integer_input(des_str):
	cor_key = False
	while cor_key == False:
		try:
			ipt = int(input(des_str))
			cor_key = True
		except ValueError:
			print("Try again.")
	return ipt

def encrypt_sha512v1():
	fname = input('File name to encrypt: ')
	e_p_t_flag = False
	try:
		e_p_t = open(fname, 'r')
		e_p_t_flag = True
		e_p_t.close()
	except FileNotFoundError:
		pass
	if e_p_t_flag == True:
		pass_ok = False
		while pass_ok == False:
			passw = getpass.getpass('Password: ')
			passw_check = getpass.getpass('Confirm password: ')
			if passw == passw_check:
				pass_ok = True
			else:
				print("Passwords don't match, please retry.")
		it_amount = 1000
		k_am = 1
		try:
			k_am = int(input('Key length (X > 0) = 512 * X: [1] '))
		except ValueError:
			pass
		k_am = max(1,k_am)
		try:
			it_amount = int(input('PBKDF2 Iterations (X > 0) = 1000 * X: [1000] '))
		except ValueError:
			pass
		it_amount = max(1,it_amount)
		encrypt_file(fname,passw,'01',k_am, it_amount)
	else:
		print('File to encrypt not found.')
		time.sleep(3)
def encrypt_sha512v2():
	fname = input('File name to encrypt: ')
	e_p_t_flag = False
	try:
		e_p_t = open(fname, 'r')
		e_p_t_flag = True
		e_p_t.close()
	except FileNotFoundError:
		pass
	if e_p_t_flag == True:
		pass_ok = False
		while pass_ok == False:
			passw = getpass.getpass('Password: ')
			passw_check = getpass.getpass('Confirm password: ')
			if passw == passw_check:
				pass_ok = True
			else:
				print("Passwords don't match, please retry.")
		it_amount = 1000
		k_am = 1
		try:
			k_am = int(input('Key length (X > 0) = 512 * X: [1] '))
		except ValueError:
			pass
		k_am = max(1,k_am)
		try:
			it_amount = int(input('PBKDF2 Iterations (X > 0) = 1000 * X: [1000] '))
		except ValueError:
			pass
		it_amount = max(1,it_amount)
		encrypt_file(fname,passw,'02',k_am, it_amount)
	else:
		print('File to encrypt not found.')
		time.sleep(3)
def encrypt_rsa_sha512v1(bytestoencrypt):
	fname = input('File name to encrypt: ')
	pass_ok = False
	while pass_ok == False:
		passw = getpass.getpass('Password: ')
		passw_check = getpass.getpass('Confirm password: ')
		if passw == passw_check:
			pass_ok = True
		else:
			print("Passwords don't match, please retry.")
	it_amount = 1000
	k_am = 1
	try:
		k_am = int(input('Key length (X > 0) = 512 * X: [1] '))
	except ValueError:
		pass
	k_am = max(1,k_am)
	try:
		it_amount = int(input('PBKDF2 Iterations (X > 0) = 1000 * X: [1000] '))
	except ValueError:
		pass
	it_amount = max(1,it_amount)
	encrypt_file(fname,passw,'01',k_am, it_amount, mode="R", bytein=bytestoencrypt)

def encrypt_sha512v2():
	fname = input('File name to encrypt: ')
	e_p_t_flag = False
	try:
		e_p_t = open(fname, 'r')
		e_p_t_flag = True
		e_p_t.close()
	except FileNotFoundError:
		pass
	if e_p_t_flag == True:
		pass_ok = False
		while pass_ok == False:
			passw = getpass.getpass('Password: ')
			passw_check = getpass.getpass('Confirm password: ')
			if passw == passw_check:
				pass_ok = True
			else:
				print("Passwords don't match, please retry.")
		it_amount = 1000
		k_am = 1
		try:
			k_am = int(input('Key length (X > 0) = 512 * X: [1] '))
		except ValueError:
			pass
		k_am = max(1,k_am)
		try:
			it_amount = int(input('PBKDF2 Iterations (X > 0) = 1000 * X: [1000] '))
		except ValueError:
			pass
		it_amount = max(1,it_amount)
		encrypt_file(fname,passw,'02',k_am, it_amount)
	else:
		print('File to encrypt not found.')
		time.sleep(3)

		
def encrypt_aes_ede3_ctr():
	fname = input('File name to encrypt: ')
	e_p_t_flag = False
	try:
		e_p_t = open(fname, 'r')
		e_p_t_flag = True
		e_p_t.close()
	except FileNotFoundError:
		pass
	if e_p_t_flag == True:
		pass_ok = False
		while pass_ok == False:
			passw = getpass.getpass('Password: ')
			passw_check = getpass.getpass('Confirm password: ')
			if passw == passw_check:
				pass_ok = True
			else:
				print("Passwords don't match, please retry.")
		it_amount = 1000
		try:
			it_amount = int(input('PBKDF2 Iterations (X > 0) = 1000 * X: [1000] '))
		except ValueError:
			pass
		it_amount = max(1,it_amount)
		encrypt_file(fname,passw,'03',2, it_amount)
	else:
		print('File to encrypt not found.')
		time.sleep(3)

def encrypt_rsa_sha512v2(bytestoencrypt):
	fname = input('File name to encrypt: ')
	pass_ok = False
	while pass_ok == False:
		passw = getpass.getpass('Password: ')
		passw_check = getpass.getpass('Confirm password: ')
		if passw == passw_check:
			pass_ok = True
		else:
			print("Passwords don't match, please retry.")
	it_amount = 1000
	k_am = 1
	try:
		k_am = int(input('Key length (X > 0) = 512 * X: [1] '))
	except ValueError:
		pass
	k_am = max(1,k_am)
	try:
		it_amount = int(input('PBKDF2 Iterations (X > 0) = 1000 * X: [1000] '))
	except ValueError:
		pass
	it_amount = max(1,it_amount)
	encrypt_file(fname,passw,'02',k_am, it_amount, mode="R", bytein=bytestoencrypt)
	
def encrypt_rsa_aes_ede3_ctr(bytestoencrypt):
	fname = input('File name to encrypt: ')
	pass_ok = False
	while pass_ok == False:
		passw = getpass.getpass('Password: ')
		passw_check = getpass.getpass('Confirm password: ')
		if passw == passw_check:
			pass_ok = True
		else:
			print("Passwords don't match, please retry.")
	it_amount = 1000
	try:
		it_amount = int(input('PBKDF2 Iterations (X > 0) = 1000 * X: [1000] '))
	except ValueError:
		pass
	it_amount = max(1,it_amount)
	encrypt_file(fname,passw,'03',2, it_amount, mode="R", bytein=bytestoencrypt)

def encrypt_rsa_file_sha512v2():
	fname = input('File name to encrypt: ')
	e_p_t_flag = False
	try:
		e_p_t = open(fname, 'r')
		e_p_t_flag = True
		e_p_t.close()
	except FileNotFoundError:
		pass
	if e_p_t_flag == True:
		passw = ""
		it_amount = 1000
		k_am = 1
		keytorsaencrypt = encrypt_file(fname,passw,'02',k_am, it_amount, hdrmode="RSA")
		return keytorsaencrypt, fname
	else:
		print('File to encrypt not found.')
		time.sleep(3)
def encrypt_rsa_file_aes_ede3_ctr():
	fname = input('File name to encrypt: ')
	e_p_t_flag = False
	try:
		e_p_t = open(fname, 'r')
		e_p_t_flag = True
		e_p_t.close()
	except FileNotFoundError:
		pass
	if e_p_t_flag == True:
		passw = ""
		it_amount = 1000
		k_am = 2
		keytorsaencrypt = encrypt_file(fname,passw,'03',k_am, it_amount, hdrmode="RSA")
		return keytorsaencrypt, fname
	else:
		print('File to encrypt not found.')
		time.sleep(3)

def write_to_image(barr_to_write,image_original,image_to_write):
	orig_matrix = image_original.load()
	sw, sh = image_to_write.size
	image_to_write_matrix = image_to_write.load()
	imgp = sw * sh
	imgb = imgp * 3
	cur_w = cur_h = 0
	is_full = False
	for i in range(0,len(barr_to_write)//3):
		cur_chunk = barr_to_write[i*3:(i*3)+3]
		cur_list = bytes_to_3_bit_chunks(cur_chunk)
		for int3 in cur_list:
			r,g,b = orig_matrix[cur_w,cur_h]
			r,g,b = r & mask_remove_bit, g & mask_remove_bit, b & mask_remove_bit
			bit_r, bit_g, bit_b = int3 & 0b1, (int3 >> 1) & 0b1, (int3 >> 2) & 0b1
			nr,ng,nb = r | bit_r, g | bit_g, b | bit_b
			image_to_write_matrix[cur_w,cur_h] = nr, ng, nb
			cur_w += 1
			if cur_w % sw == 0:
				cur_h += 1
				cur_w = 0
				if cur_h == sh:
					is_full = True
	print('Image will be extra padded:',not is_full)
	while is_full == False:
		int3 = rng.randint(0,7)
		r,g,b = orig_matrix[cur_w,cur_h]
		r,g,b = r & mask_remove_bit, g & mask_remove_bit, b & mask_remove_bit
		bit_r, bit_g, bit_b = int3 & 0b1, (int3 >> 1) & 0b1, (int3 >> 2) & 0b1
		nr,ng,nb = r | bit_r, g | bit_g, b | bit_b
		image_to_write_matrix[cur_w,cur_h] = nr, ng, nb
		cur_w += 1
		if cur_w % sw == 0:
			cur_h += 1
			cur_w = 0
			if cur_h == sh:
				is_full = True
	print('Image completely padded:',is_full)
	return image_to_write
	
def read_from_image(image_to_read):
	sw, sh = image_to_read.size
	image_to_read_matrix = image_to_read.load()
	av_bits = sw*sh*3
	av_bytes = av_bits // 8
	tti = av_bytes // 3
	cur_w = cur_h = 0
	out_array = bytearray()
	for i in range(0,tti):
		cur_list = []
		for j in range(0,8):
			r,g,b = image_to_read_matrix[cur_w,cur_h]
			bit_r, bit_g, bit_b = r & 0b1, g & 0b1, b & 0b1
			cur_chk = bit_b
			cur_chk = (cur_chk << 1) | bit_g
			cur_chk = (cur_chk << 1) | bit_r
			cur_list.append(cur_chk)
			cur_w += 1
			if cur_w % sw == 0:
				cur_h += 1
				cur_w = 0
		out_array.extend(bit_3_chunks_to_bytes(cur_list))
	return out_array
	
def encrypt_image(prov_password, prov_orig_name, prov_file_name, prov_new_name):
	img_name = prov_orig_name
	img_object = Image.open(img_name)
	img_object = img_object.convert('RGB')
	size_w,size_h = img_object.size
	image_pixels = size_w*size_h
		# Method 1:
		# 1 bit per color, so 3 bits per pixel
		# 3*8 = 24, so we'll take 8 pixels per 3 bytes.
	avail_bits = image_pixels * 3
	bits_to_pad = avail_bits % 24
	avail_bytes = (avail_bits // 8)
	print('We can fit',avail_bytes-384,'bytes in the image selected.')
	print('Actually there are',avail_bytes,'available')
	file_name = prov_file_name
	pass_to_use = prov_password
	fte = open(file_name,'rb')
	fte_r = bytearray(fte.read())
	fte_r_l = len(fte_r)
	fte.close()
	print('Your file length is:',fte_r_l,'bytes')
	if fte_r_l > avail_bytes:
		raise FileWillNotFit
	save_name = prov_new_name
	save_object = Image.new('RGB',img_object.size)
	bytearray_to_save = bytearray()
	salt_1 = create_random_key(64)
	key_1 = create_random_key(64)
	xor_1 = create_key_xor_mask(salt_1,pass_to_use)
	ekey_1 = do_xor_on_bytes(key_1,xor_1)
	bytearray_to_save.extend(salt_1)
	bytearray_to_save.extend(ekey_1)
	salt_2 = create_random_key(64)
	key_2 = create_random_key(64)
	xor_2 = create_key_xor_mask(salt_2,pass_to_use)
	ekey_2 = do_xor_on_bytes(key_2,xor_2)
	bytearray_to_save.extend(salt_2)
	bytearray_to_save.extend(ekey_2)
	key_to_use = (key_1+key_2)
	crypto_object = aes256_ede3_ctr(key_to_use, mode="BYTES")
	bytearray_to_encrypt = bytearray()
	bytearray_to_encrypt.extend(int_to_big_endian(fte_r_l,pad_to=64))
	bytearray_to_encrypt.extend(fte_r)
	len_barr = len(bytearray_to_encrypt)
	timestopad = 64-(len_barr%64)
	for i in range(0,timestopad):
		bytearray_to_encrypt.append(rng.randint(0,255))
	timestoencrypt = len(bytearray_to_encrypt) // 64
	for i in range(0,timestoencrypt):
		cc = bytearray_to_encrypt[(i*64):(i*64)+64]
		cbx = crypto_object.get_bytes_to_xor()
		ce = do_xor_on_bytes(cc,cbx)
		bytearray_to_save.extend(ce)
	bytestopad = avail_bytes - (len(bytearray_to_save)+64)
	for i in range(0,bytestopad):
		bytearray_to_save.append(rng.randint(0,255))
	hmackey_enc = hashlib.sha512(bytearray(hashlib.sha512(key_to_use).digest())+bytearray(hashlib.sha256(key_to_use).digest())+bytearray(hashlib.md5(key_to_use).digest())).digest()
	f_hash = hmac.new(hmackey_enc,msg=bytearray_to_save,digestmod=hashlib.sha512).digest()
	bytearray_to_save.extend(f_hash)
	save_object = write_to_image(bytearray_to_save,img_object,save_object)
	save_object.save(save_name,format="PNG")
	save_object.close()
	img_object.close()
	
def decrypt_image(prov_password, prov_orig_name, prov_file_name, hmac_override=False):
	img_name = prov_orig_name
	pass_to_use = prov_password
	file_name = prov_file_name
	img_object = Image.open(img_name)
	read_bytearray = read_from_image(img_object)
	s1 = read_bytearray[:64]
	ek1 = read_bytearray[64:128]
	s2 = read_bytearray[128:192]
	ek2 = read_bytearray[192:256]
	xor1 = create_key_xor_mask(s1,pass_to_use)
	xor2 = create_key_xor_mask(s2,pass_to_use)
	k1 = do_xor_on_bytes(ek1,xor1)
	k2 = do_xor_on_bytes(ek2,xor2)
	key_to_use = k1+k2
	hmackey_enc = hashlib.sha512(bytearray(hashlib.sha512(key_to_use).digest())+bytearray(hashlib.sha256(key_to_use).digest())+bytearray(hashlib.md5(key_to_use).digest())).digest()
	hmac_array = read_bytearray[-64:]
	f_hash = hmac.new(hmackey_enc,msg=read_bytearray[:-64],digestmod=hashlib.sha512).digest()
	hmac_valid = False
	hmac_override = False
	if hmac.compare_digest(f_hash,hmac_array) == True:
		hmac_valid = True
	else:
		print("-------------WARNING----------------")
		print("------------------------------------")
		print("------------------------------------")
		print("HMAC MISMATCH, FILE COULD BE ALTERED")
		print("------------------------------------")
		print("------------------------------------")
		print("-------------WARNING----------------")
	print("HMAC CALC:",bytes.decode(binascii.hexlify(f_hash)))
	print("HMAC READ:",bytes.decode(binascii.hexlify(read_bytearray[-64:])))
	if hmac_valid == False:
		print()
		hov = input("Press 'Y' to override")
		if hov == 'Y' or hov == 'y':
			hmac_override = True
	if hmac_valid == True or hmac_override == True:
		crypto_object = aes256_ede3_ctr(key_to_use, mode="BYTES")
		xor_len = crypto_object.get_bytes_to_xor()
		barr_len = do_xor_on_bytes(read_bytearray[256:320],xor_len)
		int_len = big_endian_to_int(barr_len)
		timestopad = 64-(int_len%64)
		decrypt_bytearray = read_bytearray[320:320+int_len+timestopad]
		file_bytearray = bytearray()
		ttd = len(decrypt_bytearray) // 64
		for i in range(0,ttd):
			cc = decrypt_bytearray[(i*64):(i*64)+64]
			cbx = crypto_object.get_bytes_to_xor()
			ce = do_xor_on_bytes(cc,cbx)
			file_bytearray.extend(ce)
		file_bytearray = file_bytearray[0:int_len]
		file_object_save = open(file_name,'wb')
		file_object_save.write(file_bytearray)
		file_object_save.close()

def check_header_image(prov_password, prov_orig_name):
	img_name = prov_orig_name
	pass_to_use = prov_password
	img_object = Image.open(img_name)
	read_bytearray = read_from_image(img_object)
	#print(list(read_bytearray[0:16]))
	#print('BARRLEN:',len(read_bytearray))
	s1 = read_bytearray[:64]
	ek1 = read_bytearray[64:128]
	s2 = read_bytearray[128:192]
	ek2 = read_bytearray[192:256]
	xor1 = create_key_xor_mask(s1,pass_to_use)
	xor2 = create_key_xor_mask(s2,pass_to_use)
	k1 = do_xor_on_bytes(ek1,xor1)
	k2 = do_xor_on_bytes(ek2,xor2)
	key_to_use = k1+k2
	hmackey_enc = hashlib.sha512(bytearray(hashlib.sha512(key_to_use).digest())+bytearray(hashlib.sha256(key_to_use).digest())+bytearray(hashlib.md5(key_to_use).digest())).digest()
	hmac_array = read_bytearray[-64:]
	f_hash = hmac.new(hmackey_enc,msg=read_bytearray[:-64],digestmod=hashlib.sha512).digest()
	hmac_valid = False
	print("HMAC CALC:",bytes.decode(binascii.hexlify(f_hash)))
	print("HMAC READ:",bytes.decode(binascii.hexlify(read_bytearray[-64:])))
	print()
	if hmac.compare_digest(f_hash,hmac_array) == True:
		hmac_valid = True
	if hmac_valid == True:
		crypto_object = aes256_ede3_ctr(key_to_use, mode="BYTES")
		xor_len = crypto_object.get_bytes_to_xor()
		barr_len = do_xor_on_bytes(read_bytearray[256:320],xor_len)
		int_len = big_endian_to_int(barr_len)
		print('HMAC OK')
		print('File length is:',int_len,'bytes')
	else:
		print("-------------WARNING----------------")
		print("------------------------------------")
		print("------------------------------------")
		print("HMAC MISMATCH, FILE COULD BE ALTERED")
		print("------------------------------------")
		print("------------------------------------")
		print("-------------WARNING----------------")
		
		
		
class rsa_keystore(object):
	# e = 65537 fixed
	def __init__(self):
		self.key_list = []
		self.key_fingerprint_list = []
		#self.key_type_list = []
	def generate_key(self):
		length_ok = False
		while length_ok == False:
			try:
				cur_att_len = int(input("Desired key length, >= 4096 bit and multiple of 256: [4096]"))
				if cur_att_len < 4096 or cur_att_len % 256 != 0:
					print("Unsupported key length")
					print("Common values are 4096, 6144, 8192 bits")
					print("Please try again")
				else:
					length_ok = True
			except ValueError:
				print("Using default of 4096 bit RSA key")
				length_ok = True
				cur_att_len = 4096
		key = RSA.generate(cur_att_len)
		self.key_list.append(key)
		self.update_fingerprints()
	def update_fingerprints(self):
		self.key_fingerprint_list = []
		for i in range(0,len(self.key_list)):
			self.key_fingerprint_list.append(hashlib.sha256(bytes(str(self.key_list[i].n).encode())).hexdigest())
	def view_keys(self):
		if len(self.key_fingerprint_list) == 0:
			print("No keys found")
		else:
			for i in range(0,len(self.key_fingerprint_list)):
				print("Key number:",i+1)
				print("Fingerprint",self.key_fingerprint_list[i])
				print("Size",self.key_list[i].size())
				print("Private key in possesion:", self.key_list[i].has_private())
	def export_key(self):
		kte = force_integer_input("Key to export:")-1
		try:
			kte_ac = self.key_list[kte]
			kte_n = kte_ac.n
			kte_str = str(kte_n)
			kte_hasprivate = kte_ac.has_private()
			if kte_hasprivate == True:
				export_priv = False
				epprompt = str(input("Export also your private key? [N]"))
				if epprompt == "Y" or epprompt == "y":
					export_priv = True
				if export_priv == True:
					kte_d = kte_ac.d
					kte_str = kte_str + "," + str(kte_d)
			print('2: SHA-512 with key rotation, hash chain and plaintext feedback')
			print('3: 3AES-EDE in CTR mode with independent keys and IV. 512-bit eq.')
			ver_rsa = 3
			try:
				ver_rsa = int(input('Version: [3] '))
			except ValueError:
				pass
			if ver_rsa == 2:
				encrypt_rsa_sha512v2(kte_str.encode())
			elif ver_rsa == 3:
				encrypt_rsa_aes_ede3_ctr(kte_str.encode())
			else:
				print('Try again!')
		except IndexError:
			print("Key not in keystore.")
	def import_key(self):
		fname = input('File name to decrypt: ')
		passw = getpass.getpass('Password: ')
		keyraw = decrypt_file(fname,passw, False, mode="R")
		if type(keyraw) == str:
			print("Decryption Failed")
			return "F"
		else:
			keydec = (keyraw.decode()).split(",")
		if len(keydec) == 1:
			tuple_to_use = int(keydec[0]),65537
		elif len(keydec) == 2:
			tuple_to_use = int(keydec[0]),65537,int(keydec[1])
		self.key_list.append(RSA.construct(tuple_to_use))
		self.update_fingerprints()
	def delete_key(self):
		kte = force_integer_input("Key to delete:")-1
		self.key_list.pop(kte)
		self.update_fingerprints()
	def encrypt_file_rsa(self):
		ktu = force_integer_input("Key to use:")-1
		try:
			ktu_ac = self.key_list[ktu]
			print('2: SHA-512 with key rotation, hash chain and plaintext feedback')
			print('3: 3AES-EDE in CTR mode with independent keys and IV. 512-bit eq.')
			ver_rsa = 3
			try:
				ver_rsa = int(input('Version: [3] '))
			except ValueError:
				pass
			if ver_rsa == 2:
				kte, fnhd = encrypt_rsa_file_sha512v2()
			elif ver_rsa == 3:
				kte, fnhd = encrypt_rsa_file_aes_ede3_ctr()
			else:
				print('Try again!')
			print(kte)
			fnhd = fnhd + ".rsaheader"
			rsacipher = PKCS1_OAEP.new(ktu_ac,hashAlgo=SHA512)
			ciphered_header = rsacipher.encrypt(kte)
			rsah = open(fnhd,"wb")
			rsah.write(ciphered_header)
			rsah.close()
		except IndexError:
			print("Key not in keystore")
	def decrypt_file_rsa(self):
		ktu = force_integer_input("Key to use:")-1
		try:
			ktu_ac = self.key_list[ktu]
			is_key_private = ktu_ac.has_private()
			if is_key_private == True:
				rsacipher = PKCS1_OAEP.new(ktu_ac,hashAlgo=SHA512)
				file_name = str(input("File name to decrypt: "))
				try:
					rsah = open(file_name+".rsaheader","rb")
				except FileNotFoundError:
					print("RSA-encrypted header not found.")
				rsah_read = rsah.read()
				rsah.close()
				try:
					deciphered_header = rsacipher.decrypt(rsah_read)
					print(deciphered_header)
					decrypt_file(file_name,"", False, hdrmode="RSA", hdrcontents=deciphered_header.decode())
				except ValueError:
					print("Decryption Incorrect. Wrong key or tampered file.")
			else:
				print("The key selected doesn't have its private decryption exponent.")
		except IndexError:
			print("Key not in keystore")
		
print('Crypto+Steganography Project')
print('V1.0.0')
print('By fabrizziop')
print('GPLv2 licence')
print('Only for testing, cannot guarantee security.')
all_done = False
cur_keystore = rsa_keystore()
while all_done == False:
	try:
		ed = int(input('1: Encrypt, 2: Decrypt, 3: Change Password, 4: Check, 5: Help, 6: RSA Operations, 7: Image Operations 99: Exit '))
	except ValueError:
		ed = 100
	if ed == 1:
		print('1: SHA-512 with key rotation and hash chain feedback')
		print('2: SHA-512 with key rotation, hash chain and plaintext feedback')
		print('3: 3AES-EDE in CTR mode with independent keys and IV. 512-bit eq.')
		ver = 3
		try:
			ver = int(input('Version: [3] '))
		except ValueError:
			pass
		if ver == 1:
			encrypt_sha512v1()
		elif ver == 2:
			encrypt_sha512v2()
		elif ver == 3:
			encrypt_aes_ede3_ctr()
	elif ed == 2:
		fname = input('File name to decrypt: ')
		passw = getpass.getpass('Password: ')
		decrypt_file(fname,passw, False)
	elif ed == 3:
		fname = input('File name to change password: ')
		passw = getpass.getpass('Old Password: ')
		pass_ok = False
		while pass_ok == False:
			passwn = getpass.getpass('Password: ')
			passwn_check = getpass.getpass('Confirm password: ')
			if passwn == passwn_check:
				pass_ok = True
			else:
				print("Passwords don't match, please retry.")
		change_password(fname, passw, passwn)
	elif ed == 4:
		fname = input('File name to check: ')
		have_pass = str(input('Authenticate & Verify with password? Y/N [N] '))
		p_flag = False
		found_header = False
		if have_pass.upper() == 'Y':
				passw = getpass.getpass('Password: ')
				p_flag = True
		nfname = fname + '.header'
		try:
			nf = open(nfname,'r')
			header_str = nf.read()
			nf.close()
			found_header = True
		except FileNotFoundError:
			print("Header is missing!")
			time.sleep(3)
		if found_header == True:
			key_amount = int(header_str[0:4],16)
			pbkdf2_iterations = int(header_str[4:8],16)
			pbkdf2_real_iters = pbkdf2_iterations * 1000
			ver = header_str[(key_amount*256)+8:(key_amount*256)+10]
			length = header_str[(key_amount*256)+10:-128]
			if p_flag == True:
					hmac_in_hdr = header_str[-128:]
					k_pbkdf_hmac = hashlib.pbkdf2_hmac('sha512', passw.encode(), bytes.fromhex(header_str[8:136]), pbkdf2_real_iters*4)
					hmac_val = hmac.new(k_pbkdf_hmac, header_str[:-128].encode(), hashlib.sha512).hexdigest()
					if hmac_in_hdr == hmac_val:
						print('The header is OK')
						print('The following data is authenticated')
					else:
						print('Wrong password or tampered header')
						print('The following data is unauthenticated')
			else:
				print('The following data is unauthenticated')
			print('Key size:', key_amount*512)
			print('PBKDF2 iterations:', pbkdf2_real_iters)
			print('Encryption Version:', ver)
			print('Encrypted file length (bytes):', int(length,16))
			if p_flag == True:
				want_to_try_decrypt = str(input('Verify file integrity? Y/N [N] '))
				if want_to_try_decrypt.upper() == 'Y':
					print(decrypt_file(fname, passw, True))
					time.sleep(3)
			else:
				time.sleep(3)
	elif ed == 5:
		print('AES256-EDE3 should be equivalent to a 512-bit security level')
		print('All HMACs used are SHA-512 based')
		time.sleep(20)
	elif ed == 99:
		all_done = True
	elif ed == 6:
		rsa_loop = True
		while rsa_loop == True:
			try:	
				rsaop = int(input("1: Generate Key, 2: Export Key, 3: Import Key, 4: View Keys, 5: Delete Key, 6: Encrypt, 7: Decrypt 99: Exit "))
			except ValueError:
				rsaop = 100
			if rsaop == 1:
				cur_keystore.generate_key()
			elif rsaop == 2:
				cur_keystore.export_key()
			elif rsaop == 3:
				cur_keystore.import_key()
			elif rsaop == 4:
				cur_keystore.view_keys()
			elif rsaop == 5:
				cur_keystore.delete_key()
			elif rsaop == 6:
				cur_keystore.encrypt_file_rsa()
			elif rsaop == 7:
				cur_keystore.decrypt_file_rsa()
			elif rsaop == 99:
				rsa_loop = False
			else:
				print('Invalid option')
	elif ed == 7:
		image_loop = True
		while image_loop == True:
			print('1: Encrypt File, 2: Decrypt File, 3: Test File, 99: Exit')
			cur_image_op = input_int_until_list_or_default([1,2,3,98,99],98)
			if cur_image_op == 1:
				print('Image to encrypt into: ')
				op_in = input_file_until_file_found()
				print('File to place inside image: ')
				op_fte = input_file_until_file_found()
				print('New image name: ')
				op_dest = input()
				op_passw = input_password_until_match()
				encrypt_image(op_passw, op_in, op_fte, op_dest)
			elif cur_image_op == 2:
				print('Image to decrypt from: ')
				op_in = input_file_until_file_found()
				print('File to create: ')
				op_fte = input()
				op_passw = getpass.getpass("Password:")
				decrypt_image(op_passw, op_in, op_fte)
			elif cur_image_op == 3:
				print('Image to decrypt from: ')
				op_in = input_file_until_file_found()
				op_passw = getpass.getpass("Password:")
				check_header_image(op_passw, op_in)
			elif cur_image_op == 99:
				image_loop = False
	else:
		print('Invalid option')
