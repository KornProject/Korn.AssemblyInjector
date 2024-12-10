unsafe record ProcedureStack(int Size)
{
    public List<ProcedureLocalVariable> LocalVariables = [];
    int currentOffset = 0;

    public ProcedureLocalVariable CreateLocalVariable<T>() where T : unmanaged
    {
        var tsize = sizeof(T);
        var variable = new ProcedureLocalVariable(tsize, Size - currentOffset - tsize);

        LocalVariables.Add(variable);
        currentOffset += tsize;

        return variable;
    }
}