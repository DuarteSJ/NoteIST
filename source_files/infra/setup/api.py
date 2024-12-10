# setup/api.py
from fastapi import FastAPI, HTTPException, Depends
from models import DocumentModel
from dbOperations import DocumentCRUD
from typing import List  # Import List for type hinting

# Create FastAPI application
app = FastAPI(
    title="Team Document Management API",
    description="API for managing documents with MongoDB",
    version="1.0.0",
)


# Dependency to get CRUD operations
def get_document_crud():
    return DocumentCRUD()


# CRUD API Endpoints
@app.post("/documents/", response_model=DocumentModel)
def create_document(
    document: DocumentModel, crud: DocumentCRUD = Depends(get_document_crud)
):
    """Create a new document"""
    return crud.create(document)


@app.get("/documents/", response_model=List[DocumentModel])
def read_documents(crud: DocumentCRUD = Depends(get_document_crud)):
    """Retrieve all documents"""
    return crud.read_all()


@app.get("/documents/{document_id}", response_model=DocumentModel)
def read_document(document_id: str, crud: DocumentCRUD = Depends(get_document_crud)):
    """Retrieve a single document by ID"""
    document = crud.read_by_id(document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    return document


@app.put("/documents/{document_id}", response_model=DocumentModel)
def update_document(
    document_id: str,
    document: DocumentModel,
    crud: DocumentCRUD = Depends(get_document_crud),
):
    """Update an existing document"""
    updated_document = crud.update(document_id, document)
    if not updated_document:
        raise HTTPException(status_code=404, detail="Document not found")
    return updated_document


@app.delete("/documents/{document_id}")
def delete_document(document_id: str, crud: DocumentCRUD = Depends(get_document_crud)):
    """Delete a document by ID"""
    success = crud.delete(document_id)
    if not success:
        raise HTTPException(status_code=404, detail="Document not found")
    return {"message": "Document deleted successfully"}


# Run the application
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
