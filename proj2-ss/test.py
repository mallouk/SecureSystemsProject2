first_line=''
brand='fjowfowfjwofhofwj fowfowj'
with open('/home/matthew/git/SecureSystemsProject2/proj2-ss/textfile', 'r') as metafile:
    with open('/home/matthew/git/SecureSystemsProject2/proj2-ss/textfile1', 'w') as metafile_w:
        first_line = metafile.readline().replace('\n','')
        parsed_first_line = first_line.split('***')
        first_line=''
        
        print len(parsed_first_line)-1
        print parsed_first_line
        for x in range(0, len(parsed_first_line)-1):
            first_line+=parsed_first_line[x]+'***'
        first_line+='YES'
        metafile_w.write(first_line)
        for line in metafile:
            metafile_w.write(line)
                
        metafile_w.write('\n'+brand)
        metafile_w.close()
        metafile.close()
