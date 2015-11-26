class Student:
    stuName = "Matthew"
    stuAge = 23

    def setName(self, name):
        self.stuName = name
    
    def getName(self):
        return self.stuName

    def getAge(self):
        return self.stuAge

    
moo=Student()
print moo.getAge()
print moo.getName()
moo.setName("Bob")
print moo.getName()
