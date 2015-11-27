with open('/home/matthew/git/SecureSystemsProject2/proj2-ss/textfile', 'r') as metafile:
    line_counter = 1
    for line in metafile:
        if (line_counter == 1):
            #print line.replace('\n','')
            line_parse = line.replace('\n','').split('***')
            if line_parse[len(line_parse)-1] == 'NO'
            line_counter+=1
