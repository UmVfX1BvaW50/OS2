cmd_/home/ubuntu/OS2/Module.symvers := sed 's/\.ko$$/\.o/' /home/ubuntu/OS2/modules.order | scripts/mod/modpost -m -a  -o /home/ubuntu/OS2/Module.symvers -e -i Module.symvers   -T -
