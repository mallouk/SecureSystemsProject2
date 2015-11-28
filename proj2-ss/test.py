import time

curr_time = int(round(time.time()))
print curr_time
time = 30
exp_time = curr_time + (time)
print exp_time
print exp_time - curr_time
first_line=''
brand='fjowfowfjwofhofwj fowfowj'
with open('/home/matthew/git/SecureSystemsProject2/proj2-ss/textfile', 'r') as metafile:
    with open('/home/matthew/git/SecureSystemsProject2/proj2-ss/textfile1', 'w') as metafile_w:
        first_line = metafile.readline().replace('\n','')
        parsed_first_line = first_line.split('***')
        first_line=''
        for x in range(0, len(parsed_first_line)-1):
            first_line+=parsed_first_line[x]+'***'
            
            first_line+='YES\n'
            metafile_w.write(first_line)
            for line in metafile:
                metafile_w.write(line+'\n')
                
            metafile_w.write(brand)
            metafile_w.close()
            metafile.close()
