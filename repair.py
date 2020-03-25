# -*- coding: utf-8 -*-
import json
import string
import base64
import getopt
import sys
import hashlib
import zlib
import struct
import os
'''
遇到文中的分号就换行
'''
def delblankline():
	global insfilename
	infopen = open(insfilename, 'r',encoding="utf-8")
	outfopen = open(insfilename + '_out', 'w',encoding="utf-8")
	db = infopen.read()
	outfopen.write(db.replace(';','\n'))
	outfopen.close()
	f = open(insfilename + '_out', 'rb+')
	f.seek(-1 ,os.SEEK_END)
	if f.read() == "\n":
		f.seek(-1 ,os.SEEK_END)
		f.truncate()
	infopen.close()
	f.close()
	
'''
读取bin文件一行数据并返回以json格式返回数据
'''	
def read_one_line(line):
	#print(line)
	frags = line.split(',')
	if len(frags) == 5:
		_name = frags[0].split(':')[1]
		_method_idx = int(frags[1].split(':')[1])
		_offset =  int(frags[2].split(':')[1])
		_code_item_len = int(frags[3].split(':')[1])
		_ins = frags[4].split(':')[1].replace("}\n", "")
		return _name,_method_idx,_offset,_code_item_len,_ins
	else:
		return '',-1,-1,-1,''	

def init():
	global filename
	global insfilename
	global method_name
	global all_methods
	try:
		opts, args = getopt.getopt(sys.argv[1:], "had:i:m:", ["all","dumpdexfile=", "insfile=","method_name="])
	except getopt.GetoptError:
		print('repair.py -d <dumpdexfile> -i <insfile> (-m <method_name> | -a)')
		sys.exit(2)
	if len(opts)<=0:
		print('repair.py -d <dumpdexfile> -i <insfile> (-m <method_name> | -a)')
		sys.exit()
	for opt, arg in opts:
		if opt in ("-h", "--help"):
			print('repair.py -d <dumpdexfile> -i <insfile> (-m <method_name> | -a)' )
			sys.exit()
		if opt in ("-d", "--dumpdexfile"):
			filename = arg
		elif opt in ("-i", "--insfile"):
			insfilename = arg
		elif opt in ("-a","--all"):
			all_methods = True
			method_name = 'all'
		elif opt in ("-m","--method_name"):
			method_name = arg
			print(arg)
			all_methods = False		
	print('dumpdex file:', filename)
	print('ins file:', insfilename)
	print('repair method name:', method_name)
	


	
		
	
class dex_method:
	name = ''
	method_idx = 0
	offset = 0
	code_item_len = 0
	ins_raw = ''
	ins = b''
	def __init__(self,_name,_method_idx,_offset,_code_item_len,_ins):
		self.ins_raw = _ins
		self.name,self.method_idx,self.offset,self.code_item_len,self.ins = _name,_method_idx,_offset,_code_item_len,base64.b64decode(_ins)
		#print(_name,_method_idx,_offset,_code_item_len,self.ins_raw)
	
	def repair_dex(self,fd):
		if self.offset > 0:
			fd.seek(self.offset, 0)
			if len(self.ins) == self.code_item_len:
				#print('reapir method = ',self.name,'repair code = ',self.ins_raw)
				fd.write(self.ins)	
		
def main():
	init()
	global filename
	global insfilename
	global method_name
	global all_methods
	delblankline()
	dex_file = open(filename,'rb+')			
	#bin_file = 
	if all_methods:
		with open(insfilename + '_out',encoding='utf-8') as f:
			for line in f:
				_name,_method_idx,_offset,_code_item_len,_ins = read_one_line(line)
				method = dex_method(_name, _method_idx, _offset, _code_item_len, _ins)
				method.repair_dex(dex_file)
	else:
		found = False
		with open(insfilename + '_out',encoding='utf-8') as f:
			for line in f:
				_name,_method_idx,_offset,_code_item_len,_ins = read_one_line(line)
				if method_name in _name:
					found = True
					method = dex_method(_name, _method_idx, _offset, _code_item_len, _ins)
					print('find method = ' + method.name)
					method.repair_dex(dex_file)
				else:
					pass
		if found == False:
			print('don\'t find method = ',method_name)		
				#break
	
		
if __name__ == '__main__':
	main()
		

