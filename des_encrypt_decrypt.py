import sys

#python version information
Python_version = sys.version_info[0]

#Cyphering modes
Electronic_Code_Block =	0
code_block_chain =	1

#padding modes
Normal_P = 1
PKCS5_P = 2


#base class.
class base_class_des(object):
	def __init__(self, mode=Electronic_Code_Block, IV=None, pad=None, padmode=Normal_P):
		if IV:
			IV = self.unicode_guard(IV)
		if pad:
			pad = self.unicode_guard(pad)
		self.block_size = 8
		if pad and padmode == PKCS5_P:
			raise ValueError("Cannot use a pad character with PKCS5_P")
		if IV and len(IV) != self.block_size:
			raise ValueError("Invalid Initial Value (IV), must be a multiple of " + str(self.block_size) + " bytes")

		#Constructor variables
		self._mode = mode
		self._iv = IV
		self._padding = pad
		self._padmode = padmode

	def Key_G(self):
		return self.__key

	def Key_S(self, key):
		key = self.unicode_guard(key)
		self.__key = key

	def Mode_G(self):
		return self._mode

	def Mode_S(self, mode):
		self._mode = mode

	def Pad_G(self):
		return self._padding

	def Pad_S(self, pad):
		if pad is not None:
			pad = self.unicode_guard(pad)
		self._padding = pad

	def P_mode_S(self):
		return self._padmode
		
	def setPadMode(self, mode):
		self._padmode = mode

	def Get_bytes(self):
		return self._iv

	def Set_bytes(self, IV):
		if not IV or len(IV) != self.block_size:
			raise ValueError("Must be block size: " + str(self.block_size) + " bytes")
		IV = self.unicode_guard(IV)
		self._iv = IV

	def padding_data(self, data, pad, padmode):
		# import pad data
		if padmode is None:
			# pading mode
			padmode = self.P_mode_S()
		if pad and padmode == PKCS5_P:
			raise ValueError("Invalid pad character")

		if padmode == Normal_P:
			if len(data) % self.block_size == 0:
				# zero pading
				return data

			if not pad:
				# default pad
				pad = self.Pad_G()
			if not pad:
				raise ValueError("Invalid pad data")
			data += (self.block_size - (len(data) % self.block_size)) * pad
		
		elif padmode == PKCS5_P:
			pad_len = 8 - (len(data) % self.block_size)
			if Python_version < 3:
				data += pad_len * chr(pad_len)
			else:
				data += bytes([pad_len] * pad_len)

		return data

	def data_remove_pad(self, data, pad, padmode):
		# unpad data
		if not data:
			return data
		if pad and padmode == PKCS5_P:
			raise ValueError("Cannot use a pad character with PKCS5_P")
		if padmode is None:
			# default pad
			padmode = self.P_mode_S()

		if padmode == Normal_P:
			if not pad:
				# Get the default padding.
				pad = self.Pad_G()
			if pad:
				data = data[:-self.block_size] + \
				       data[-self.block_size:].rstrip(pad)

		elif padmode == PKCS5_P:
			if Python_version < 3:
				pad_len = ord(data[-1])
			else:
				pad_len = data[-1]
			data = data[:-pad_len]

		return data

	def unicode_guard(self, data):
		# Only accept byte strings or ascii unicode values
		if Python_version < 3:
			if isinstance(data, unicode):
				raise ValueError("pyDes can only work with bytes, not Unicode strings.")
		else:
			if isinstance(data, str):
				# Only accept ascii unicode values.
				try:
					return data.encode('ascii')
				except UnicodeEncodeError:
					pass
				raise ValueError("pyDes can only work with encoded strings, not Unicode.")
		return data

class des(base_class_des):

	# permutation table
	permute_1 = [56, 48, 40, 32, 24, 16,  8,
				0, 57, 49, 41, 33, 25, 17,
				9,  1, 58, 50, 42, 34, 26,
				18, 10,  2, 59, 51, 43, 35,
				62, 54, 46, 38, 30, 22, 14,
				6, 61, 53, 45, 37, 29, 21,
				13,  5, 60, 52, 44, 36, 28,
				20, 12,  4, 27, 19, 11,  3
	]

	# permute table rotaion.
	left_permute_rotation = [
		1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	]

	# permute table 2
	permute_table_2 = [
		13, 16, 10, 23,  0,  4,
		 2, 27, 14,  5, 20,  9,
		22, 18, 11,  3, 25,  7,
		15,  6, 26, 19, 12,  1,
		40, 51, 30, 36, 46, 54,
		29, 39, 50, 44, 32, 47,
		43, 48, 38, 55, 33, 52,
		45, 41, 49, 35, 28, 31
	]

	# first permutation
	First_permute_1 = [57, 49, 41, 33, 25, 17, 9,  1,
						59, 51, 43, 35, 27, 19, 11, 3,
						61, 53, 45, 37, 29, 21, 13, 5,
						63, 55, 47, 39, 31, 23, 15, 7,
						56, 48, 40, 32, 24, 16, 8,  0,
						58, 50, 42, 34, 26, 18, 10, 2,
						60, 52, 44, 36, 28, 20, 12, 4,
						62, 54, 46, 38, 30, 22, 14, 6
					]

	# block change table,.
	expan_table = [
		31,  0,  1,  2,  3,  4,
		 3,  4,  5,  6,  7,  8,
		 7,  8,  9, 10, 11, 12,
		11, 12, 13, 14, 15, 16,
		15, 16, 17, 18, 19, 20,
		19, 20, 21, 22, 23, 24,
		23, 24, 25, 26, 27, 28,
		27, 28, 29, 30, 31,  0
	]

	# sboxes
	sboxes = [
		# S1
		[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

		# S2
		[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

		# S3
		[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

		# S4
		[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

		# S5
		[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

		# S6
		[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

		# S7
		[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

		# S8
		[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
	]


	# permutation to get the output for s boxes.
	__p = [
			15, 6, 19, 20, 28, 11,
			27, 16, 0, 14, 22, 25,
			4, 17, 30, 9, 1, 7,
			23,13, 31, 26, 2, 8,
			18, 12, 29, 5, 21, 10,
			3, 24
		]

	# final permutation change
	final_permutation = [
						39,  7, 47, 15, 55, 23, 63, 31,
						38,  6, 46, 14, 54, 22, 62, 30,
						37,  5, 45, 13, 53, 21, 61, 29,
						36,  4, 44, 12, 52, 20, 60, 28,
						35,  3, 43, 11, 51, 19, 59, 27,
						34,  2, 42, 10, 50, 18, 58, 26,
						33,  1, 41,  9, 49, 17, 57, 25,
						32,  0, 40,  8, 48, 16, 56, 24
					]

	#enable configuration for encrypt or decrypt.
	ENCRYPT =	0x00
	DECRYPT =	0x01

	# construct
	def __init__(self, key, mode=Electronic_Code_Block, IV=None, pad=None, padmode=Normal_P):
		#block check
		if len(key) != 8:
			raise ValueError("Must be 8 byte long")
		base_class_des.__init__(self, mode, IV, pad, padmode)
		self.key_size = 8

		self.L = []
		self.R = []
		self.Kn = [ [0] * 48 ] * 16	# 48 bit keys
		self.final = []

		self.Key_S(key)

	def Key_S(self, key):
		"""Must be 8 bytes."""
		base_class_des.Key_S(self, key)
		self.sub_key_create()

	def string_to_bin(self, data):
		"""data into binary"""
		if Python_version < 3:
			data = [ord(c) for c in data]
		l = len(data) * 8
		result = [0] * l
		pos = 0
		for ch in data:
			i = 7
			while i >= 0:
				if ch & (1 << i) != 0:
					result[pos] = 1
				else:
					result[pos] = 0
				pos += 1
				i -= 1

		return result

	def bin_to_string(self, data):
		"""turn bin to string"""
		result = []
		pos = 0
		c = 0
		while pos < len(data):
			c += data[pos] << (7 - (pos % 8))
			if (pos % 8) == 7:
				result.append(c)
				c = 0
			pos += 1

		if Python_version < 3:
			return ''.join([ chr(c) for c in result ])
		else:
			return bytes(result)

	def permutate_data(self, table, block):
		"""data permutate"""
		return list(map(lambda x: block[x], table))
	
	def sub_key_create(self):
		"""Create the 16 subkeys"""
		key = self.permutate_data(des.permute_1, self.string_to_bin(self.Key_G()))
		i = 0
		# Split L and R 
		self.L = key[:28]
		self.R = key[28:]
		while i < 16:
			j = 0
			# left shifts
			while j < des.left_permute_rotation[i]:
				self.L.append(self.L[0])
				del self.L[0]

				self.R.append(self.R[0])
				del self.R[0]

				j += 1

			self.Kn[i] = self.permutate_data(des.permute_table_2, self.L + self.R)

			i += 1

	# Main part of the encryption algorithm, the number cruncher :)
	def crypt_data_des(self, block, crypt_type):
		"""Crypt the block of data """
		block = self.permutate_data(des.First_permute_1, block)
		self.L = block[:32]
		self.R = block[32:]
		#iteration adjustments.
		if crypt_type == des.ENCRYPT:
			iteration = 0
			iteration_adjustment = 1
		else:
			iteration = 15
			iteration_adjustment = -1

		i = 0
		while i < 16:
			#permutate data
			tempR = self.R[:]
			self.R = self.permutate_data(des.expan_table, self.R)
			self.R = list(map(lambda x, y: x ^ y, self.R, self.Kn[iteration]))
			B = [self.R[:6], self.R[6:12], self.R[12:18],   \
			self.R[18:24], self.R[24:30], 					\
			self.R[30:36], self.R[36:42], 					\
			self.R[42:]]

			j = 0
			Bn = [0] * 32
			pos = 0
			while j < 8:
				m = (B[j][0] << 1) + B[j][5]
				n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4]

				v = des.sboxes[j][(m << 4) + n]
				Bn[pos] = (v & 8) >> 3
				Bn[pos + 1] = (v & 4) >> 2
				Bn[pos + 2] = (v & 2) >> 1
				Bn[pos + 3] = v & 1

				pos += 4
				j += 1

			self.R = self.permutate_data(des.__p, Bn)
			self.R = list(map(lambda x, y: x ^ y, self.R, self.L))
			self.L = tempR

			i += 1
			iteration += iteration_adjustment
		#final permute
		self.final = self.permutate_data(des.final_permutation, self.R + self.L)
		return self.final


	#data encrypt.
	def crypt(self, data, crypt_type):
		"""crypt data"""

		if not data:
			return ''
		if len(data) % self.block_size != 0:
			if crypt_type == des.DECRYPT: # Decryption must work on 8 byte blocks
				raise ValueError("Invalid data length.")
			if not self.Pad_G():
				raise ValueError("Invalid data length.")
			else:
				data += (self.block_size - (len(data) % self.block_size)) * self.Pad_G()

		if self.Mode_G() == code_block_chain:
			if self.Get_bytes():
				iv = self.string_to_bin(self.Get_bytes())
			else:
				raise ValueError("For code_block_chain mode, you must supply the Initial Value (IV) for ciphering")

		# Split the data into blocks
		i = 0
		dict = {}
		result = []

		while i < len(data):
		
			block = self.string_to_bin(data[i:i+8])
			if self.Mode_G() == code_block_chain:
				if crypt_type == des.ENCRYPT:
					block = list(map(lambda x, y: x ^ y, block, iv))
				block_proc = self.crypt_data_des(block, crypt_type)

				if crypt_type == des.DECRYPT:
					block_proc = list(map(lambda x, y: x ^ y, block_proc, iv))
					iv = block
				else:
					iv = block_proc
			else:
				block_proc = self.crypt_data_des(block, crypt_type)

			result.append(self.bin_to_string(block_proc))
			i += 8
		if Python_version < 3:
			return ''.join(result)
		else:
			return bytes.fromhex('').join(result)

	def encrypt(self, data, pad=None, padmode=None):
		data = self.unicode_guard(data)
		if pad is not None:
			pad = self.unicode_guard(pad)
		data = self.padding_data(data, pad, padmode)
		return self.crypt(data, des.ENCRYPT)

	def decrypt(self, data, pad=None, padmode=None):
		data = self.unicode_guard(data)
		if pad is not None:
			pad = self.unicode_guard(pad)
		data = self.crypt(data, des.DECRYPT)
		return self.data_remove_pad(data, pad, padmode)

class triple_des(base_class_des):
	def __init__(self, key, mode=Electronic_Code_Block, IV=None, pad=None, padmode=Normal_P):
		base_class_des.__init__(self, mode, IV, pad, padmode)
		self.Key_S(key)

	def Key_S(self, key):
		self.key_size = 24  #key size
		if len(key) != self.key_size:
			if len(key) == 16: #key size
				self.key_size = 16
			else:
				raise ValueError("key must br 16 byte or 24 byte")
		if self.Mode_G() == code_block_chain:
			if not self.Get_bytes():
				# Use the first 8 bytes of the key
				self._iv = key[:self.block_size]
			if len(self.Get_bytes()) != self.block_size:
				raise ValueError("must be 8 byte")
		self.__key1 = des(key[:8], self._mode, self._iv,
				  self._padding, self._padmode)
		self.__key2 = des(key[8:16], self._mode, self._iv,
				  self._padding, self._padmode)
		if self.key_size == 16:
			self.__key3 = self.__key1
		else:
			self.__key3 = des(key[16:], self._mode, self._iv,
					  self._padding, self._padmode)
		base_class_des.Key_S(self, key)


	def Mode_S(self, mode):
		base_class_des.Mode_S(self, mode)
		for key in (self.__key1, self.__key2, self.__key3):
			key.Mode_S(mode)

	def Pad_S(self, pad):
		base_class_des.Pad_S(self, pad)
		for key in (self.__key1, self.__key2, self.__key3):
			key.Pad_S(pad)

	def setPadMode(self, mode):
		base_class_des.setPadMode(self, mode)
		for key in (self.__key1, self.__key2, self.__key3):
			key.setPadMode(mode)

	def Set_bytes(self, IV):
		base_class_des.Set_bytes(self, IV)
		for key in (self.__key1, self.__key2, self.__key3):
			key.Set_bytes(IV)

	def encrypt(self, data, pad=None, padmode=None):
		ENCRYPT = des.ENCRYPT
		DECRYPT = des.DECRYPT
		data = self.unicode_guard(data)
		if pad is not None:
			pad = self.unicode_guard(pad)
		# data padding
		data = self.padding_data(data, pad, padmode)
		if self.Mode_G() == code_block_chain:
			self.__key1.Set_bytes(self.Get_bytes())
			self.__key2.Set_bytes(self.Get_bytes())
			self.__key3.Set_bytes(self.Get_bytes())
			i = 0
			result = []
			while i < len(data):
				block = self.__key1.crypt(data[i:i+8], ENCRYPT)
				block = self.__key2.crypt(block, DECRYPT)
				block = self.__key3.crypt(block, ENCRYPT)
				self.__key1.Set_bytes(block)
				self.__key2.Set_bytes(block)
				self.__key3.Set_bytes(block)
				result.append(block)
				i += 8
			if Python_version < 3:
				return ''.join(result)
			else:
				return bytes.fromhex('').join(result)
		else:
			data = self.__key1.crypt(data, ENCRYPT)
			data = self.__key2.crypt(data, DECRYPT)
			return self.__key3.crypt(data, ENCRYPT)

	def decrypt(self, data, pad=None, padmode=None):
		ENCRYPT = des.ENCRYPT
		DECRYPT = des.DECRYPT
		data = self.unicode_guard(data)
		if pad is not None:
			pad = self.unicode_guard(pad)
		if self.Mode_G() == code_block_chain:
			self.__key1.Set_bytes(self.Get_bytes())
			self.__key2.Set_bytes(self.Get_bytes())
			self.__key3.Set_bytes(self.Get_bytes())
			i = 0
			result = []
			while i < len(data):
				iv = data[i:i+8]
				block = self.__key3.crypt(iv,    DECRYPT)
				block = self.__key2.crypt(block, ENCRYPT)
				block = self.__key1.crypt(block, DECRYPT)
				self.__key1.Set_bytes(iv)
				self.__key2.Set_bytes(iv)
				self.__key3.Set_bytes(iv)
				result.append(block)
				i += 8
			if Python_version < 3:
				data = ''.join(result)
			else:
				data = bytes.fromhex('').join(result)
		else:
			data = self.__key3.crypt(data, DECRYPT)
			data = self.__key2.crypt(data, ENCRYPT)
			data = self.__key1.crypt(data, DECRYPT)
		return self.data_remove_pad(data, pad, padmode)
