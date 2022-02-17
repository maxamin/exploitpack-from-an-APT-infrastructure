import sys, os

def parse_rpc_list(program):
  filename = os.path.join(os.getcwd(), '3rdparty/D2SEC/libs/proto/rpc.list')
  rpclist = open(filename, 'r').readlines()
  for rpc in rpclist:
    rpc = rpc[:-1]
    rpc = rpc.split()
    if len(rpc) == 0: continue  
    if rpc[0] == '#': continue
    if int(rpc[1]) == int(program): return rpc[0]
