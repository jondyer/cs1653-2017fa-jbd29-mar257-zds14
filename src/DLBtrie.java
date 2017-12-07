import java.util.Scanner;
import java.io.*;
import java.util.ArrayList;

public class DLBtrie<T>
{
  // fields
  private DLBnode root;         // head of topmost LList in this trie
  private int count;            // total number of values contained in this trie

  // constructors
  public DLBtrie()
  {
    root = null;
    count = 0;
  }

  // methods
  public void insert(String key, T value)
  {
    root = insert(root, key, value, 0);
  }

  public DLBnode insert(DLBnode aNode, String key, T value, int counter)
  {
    char current = key.charAt(counter);                   // retrieve current character in key

    if(aNode==null)                                       // if we have to create a new node
    {
      aNode = new DLBnode();
      aNode.keyData = current;
    }
    if((counter==key.length()-1) && (current==aNode.keyData))    // check if we're on the last character of the key
    {                                                           // if so:
        if(aNode.data==null) count++;                       // increment the total count if value didn't exist before
        aNode.data = value;                                 // assign the new value to the node
        return aNode;
    }
    if(aNode.keyData==current)                         // what to do if the current char of key matches this node
    {
      if(!hasChild(aNode))
        aNode.child = insert(aNode.child, key, value, ++counter);
      else
        insert(aNode.child, key, value, ++counter);
    }
    else
    {
      if(!hasSib(aNode))
        aNode.rightSib = insert(aNode.rightSib, key, value, counter);
      else
        insert(aNode.rightSib, key, value, counter);
    }
    return aNode;
  }


  public boolean contains(String key)
  {
    return (get(key)!=null);
  }

  public T get(String key)
  {
    DLBnode result = get(root, key, 0);
    if(result==null) return null;
    return result.data;
  }

  private DLBnode get(DLBnode aNode, String key, int counter)       // recursive method to cycle through key
  {
    if(aNode==null) return null;                          // if node is empty (ie empty trie or reached end of LList or bottom of chain)
    if(key.length()==0) return aNode;
    char current = key.charAt(counter);                   // retrieve current character from string
    if(counter==key.length()-1)                           // check to see if we're on the last character of the key
    {
      if(aNode.keyData==current) return aNode;                              // if desired character is in this node, return this node
    }
    if(aNode.keyData==current)                                               //if it's a match, increment and go to child LList
    {
      return get(aNode.child, key, ++counter);
    }
    else                                                                     // if not, move to next node in LList
    {
      return get(aNode.rightSib, key, counter);
    }
  }

  private boolean hasChild(DLBnode aNode)
  {
    return (aNode.child!=null);             // returns false if null (ie no child), true otherwise (ie child)
  }

  private boolean hasSib(DLBnode aNode)
  {
    return (aNode.rightSib!=null);          // same as above
  }

  public int size()
  {
    return count;
  }

  public boolean isEmpty()
  {
    return count == 0;
  }



  private class DLBnode
  {
    // fields
    private char keyData;
    private T data;
    private DLBnode rightSib;
    private DLBnode child;

    public DLBnode() {}
  }
}
