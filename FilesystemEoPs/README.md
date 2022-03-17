# FilesystemEoPs

Exploit code for several techniques for taking advantage of filesystem-based exploit primitives.

* FolderOrFileDeleteToSystem: If you have an arbitrary folder or file delete as SYSTEM or admin, this exploit turns it into an EoP to SYSTEM.
  
  Credit: Abdelhamid Naceri (halov).
  
* FolderContentsDeleteToFolderDelete: If you have a delete of the contents of an arbitrary folder as SYSTEM/admin, or a recursive delete of a fixed but attacker-writable folder as SYSTEM/admin, this exploit turns it into an arbitrary folder delete as SYSTEM/admin. 
  
  Credit: Abdelhamid Naceri (halov).

These two can be chained together. Run FolderOrFileDeleteToSystem and wait to be prompted to trigger a folder delete. Then run FolderContentsDeleteToFolderDelete.

### Known Issues and Usage Notes

* The build will fail if the path contains spaces, hyphens or possibly certain other special characters.

* FolderOrFileDeleteToSystem: A race condition makes this exploit less than 100% reliable. Use the Release configuration. 4 processors recommended. A quiet system, where there is not much other CPU activity, is probably best. Bitness must match the target system.
