// Code generated by protoc-gen-go. DO NOT EDIT.
// source: roothash/roothash.proto

package roothash // import "github.com/oasislabs/ekiden/go/grpc/roothash"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Block struct {
	Header               *Header  `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Block) Reset()         { *m = Block{} }
func (m *Block) String() string { return proto.CompactTextString(m) }
func (*Block) ProtoMessage()    {}
func (*Block) Descriptor() ([]byte, []int) {
	return fileDescriptor_roothash_ea8a28a424a3bb97, []int{0}
}
func (m *Block) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Block.Unmarshal(m, b)
}
func (m *Block) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Block.Marshal(b, m, deterministic)
}
func (dst *Block) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Block.Merge(dst, src)
}
func (m *Block) XXX_Size() int {
	return xxx_messageInfo_Block.Size(m)
}
func (m *Block) XXX_DiscardUnknown() {
	xxx_messageInfo_Block.DiscardUnknown(m)
}

var xxx_messageInfo_Block proto.InternalMessageInfo

func (m *Block) GetHeader() *Header {
	if m != nil {
		return m.Header
	}
	return nil
}

type Nonce struct {
	Data                 []byte   `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Nonce) Reset()         { *m = Nonce{} }
func (m *Nonce) String() string { return proto.CompactTextString(m) }
func (*Nonce) ProtoMessage()    {}
func (*Nonce) Descriptor() ([]byte, []int) {
	return fileDescriptor_roothash_ea8a28a424a3bb97, []int{1}
}
func (m *Nonce) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Nonce.Unmarshal(m, b)
}
func (m *Nonce) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Nonce.Marshal(b, m, deterministic)
}
func (dst *Nonce) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Nonce.Merge(dst, src)
}
func (m *Nonce) XXX_Size() int {
	return xxx_messageInfo_Nonce.Size(m)
}
func (m *Nonce) XXX_DiscardUnknown() {
	xxx_messageInfo_Nonce.DiscardUnknown(m)
}

var xxx_messageInfo_Nonce proto.InternalMessageInfo

func (m *Nonce) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type Header struct {
	Version   uint32 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	Namespace []byte `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
	// Legacy round was here with id 3.
	Timestamp            uint64   `protobuf:"varint,4,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	HeaderType           uint32   `protobuf:"varint,5,opt,name=header_type,json=headerType,proto3" json:"header_type,omitempty"`
	PreviousHash         []byte   `protobuf:"bytes,6,opt,name=previous_hash,json=previousHash,proto3" json:"previous_hash,omitempty"`
	GroupHash            []byte   `protobuf:"bytes,7,opt,name=group_hash,json=groupHash,proto3" json:"group_hash,omitempty"`
	InputHash            []byte   `protobuf:"bytes,8,opt,name=input_hash,json=inputHash,proto3" json:"input_hash,omitempty"`
	OutputHash           []byte   `protobuf:"bytes,9,opt,name=output_hash,json=outputHash,proto3" json:"output_hash,omitempty"`
	StateRoot            []byte   `protobuf:"bytes,10,opt,name=state_root,json=stateRoot,proto3" json:"state_root,omitempty"`
	CommitmentsHash      []byte   `protobuf:"bytes,11,opt,name=commitments_hash,json=commitmentsHash,proto3" json:"commitments_hash,omitempty"`
	StorageReceipt       []byte   `protobuf:"bytes,12,opt,name=storage_receipt,json=storageReceipt,proto3" json:"storage_receipt,omitempty"`
	Round                uint64   `protobuf:"varint,13,opt,name=round,proto3" json:"round,omitempty"`
	TagHash              []byte   `protobuf:"bytes,14,opt,name=tag_hash,json=tagHash,proto3" json:"tag_hash,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Header) Reset()         { *m = Header{} }
func (m *Header) String() string { return proto.CompactTextString(m) }
func (*Header) ProtoMessage()    {}
func (*Header) Descriptor() ([]byte, []int) {
	return fileDescriptor_roothash_ea8a28a424a3bb97, []int{2}
}
func (m *Header) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Header.Unmarshal(m, b)
}
func (m *Header) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Header.Marshal(b, m, deterministic)
}
func (dst *Header) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Header.Merge(dst, src)
}
func (m *Header) XXX_Size() int {
	return xxx_messageInfo_Header.Size(m)
}
func (m *Header) XXX_DiscardUnknown() {
	xxx_messageInfo_Header.DiscardUnknown(m)
}

var xxx_messageInfo_Header proto.InternalMessageInfo

func (m *Header) GetVersion() uint32 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *Header) GetNamespace() []byte {
	if m != nil {
		return m.Namespace
	}
	return nil
}

func (m *Header) GetTimestamp() uint64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *Header) GetHeaderType() uint32 {
	if m != nil {
		return m.HeaderType
	}
	return 0
}

func (m *Header) GetPreviousHash() []byte {
	if m != nil {
		return m.PreviousHash
	}
	return nil
}

func (m *Header) GetGroupHash() []byte {
	if m != nil {
		return m.GroupHash
	}
	return nil
}

func (m *Header) GetInputHash() []byte {
	if m != nil {
		return m.InputHash
	}
	return nil
}

func (m *Header) GetOutputHash() []byte {
	if m != nil {
		return m.OutputHash
	}
	return nil
}

func (m *Header) GetStateRoot() []byte {
	if m != nil {
		return m.StateRoot
	}
	return nil
}

func (m *Header) GetCommitmentsHash() []byte {
	if m != nil {
		return m.CommitmentsHash
	}
	return nil
}

func (m *Header) GetStorageReceipt() []byte {
	if m != nil {
		return m.StorageReceipt
	}
	return nil
}

func (m *Header) GetRound() uint64 {
	if m != nil {
		return m.Round
	}
	return 0
}

func (m *Header) GetTagHash() []byte {
	if m != nil {
		return m.TagHash
	}
	return nil
}

type LatestBlockRequest struct {
	RuntimeId            []byte   `protobuf:"bytes,1,opt,name=runtime_id,json=runtimeId,proto3" json:"runtime_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LatestBlockRequest) Reset()         { *m = LatestBlockRequest{} }
func (m *LatestBlockRequest) String() string { return proto.CompactTextString(m) }
func (*LatestBlockRequest) ProtoMessage()    {}
func (*LatestBlockRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_roothash_ea8a28a424a3bb97, []int{3}
}
func (m *LatestBlockRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LatestBlockRequest.Unmarshal(m, b)
}
func (m *LatestBlockRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LatestBlockRequest.Marshal(b, m, deterministic)
}
func (dst *LatestBlockRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LatestBlockRequest.Merge(dst, src)
}
func (m *LatestBlockRequest) XXX_Size() int {
	return xxx_messageInfo_LatestBlockRequest.Size(m)
}
func (m *LatestBlockRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_LatestBlockRequest.DiscardUnknown(m)
}

var xxx_messageInfo_LatestBlockRequest proto.InternalMessageInfo

func (m *LatestBlockRequest) GetRuntimeId() []byte {
	if m != nil {
		return m.RuntimeId
	}
	return nil
}

type LatestBlockResponse struct {
	Block                *Block   `protobuf:"bytes,1,opt,name=block,proto3" json:"block,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LatestBlockResponse) Reset()         { *m = LatestBlockResponse{} }
func (m *LatestBlockResponse) String() string { return proto.CompactTextString(m) }
func (*LatestBlockResponse) ProtoMessage()    {}
func (*LatestBlockResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_roothash_ea8a28a424a3bb97, []int{4}
}
func (m *LatestBlockResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LatestBlockResponse.Unmarshal(m, b)
}
func (m *LatestBlockResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LatestBlockResponse.Marshal(b, m, deterministic)
}
func (dst *LatestBlockResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LatestBlockResponse.Merge(dst, src)
}
func (m *LatestBlockResponse) XXX_Size() int {
	return xxx_messageInfo_LatestBlockResponse.Size(m)
}
func (m *LatestBlockResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_LatestBlockResponse.DiscardUnknown(m)
}

var xxx_messageInfo_LatestBlockResponse proto.InternalMessageInfo

func (m *LatestBlockResponse) GetBlock() *Block {
	if m != nil {
		return m.Block
	}
	return nil
}

type BlockRequest struct {
	RuntimeId            []byte   `protobuf:"bytes,1,opt,name=runtime_id,json=runtimeId,proto3" json:"runtime_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BlockRequest) Reset()         { *m = BlockRequest{} }
func (m *BlockRequest) String() string { return proto.CompactTextString(m) }
func (*BlockRequest) ProtoMessage()    {}
func (*BlockRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_roothash_ea8a28a424a3bb97, []int{5}
}
func (m *BlockRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BlockRequest.Unmarshal(m, b)
}
func (m *BlockRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BlockRequest.Marshal(b, m, deterministic)
}
func (dst *BlockRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BlockRequest.Merge(dst, src)
}
func (m *BlockRequest) XXX_Size() int {
	return xxx_messageInfo_BlockRequest.Size(m)
}
func (m *BlockRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_BlockRequest.DiscardUnknown(m)
}

var xxx_messageInfo_BlockRequest proto.InternalMessageInfo

func (m *BlockRequest) GetRuntimeId() []byte {
	if m != nil {
		return m.RuntimeId
	}
	return nil
}

type BlockResponse struct {
	Block                *Block   `protobuf:"bytes,1,opt,name=block,proto3" json:"block,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BlockResponse) Reset()         { *m = BlockResponse{} }
func (m *BlockResponse) String() string { return proto.CompactTextString(m) }
func (*BlockResponse) ProtoMessage()    {}
func (*BlockResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_roothash_ea8a28a424a3bb97, []int{6}
}
func (m *BlockResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BlockResponse.Unmarshal(m, b)
}
func (m *BlockResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BlockResponse.Marshal(b, m, deterministic)
}
func (dst *BlockResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BlockResponse.Merge(dst, src)
}
func (m *BlockResponse) XXX_Size() int {
	return xxx_messageInfo_BlockResponse.Size(m)
}
func (m *BlockResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_BlockResponse.DiscardUnknown(m)
}

var xxx_messageInfo_BlockResponse proto.InternalMessageInfo

func (m *BlockResponse) GetBlock() *Block {
	if m != nil {
		return m.Block
	}
	return nil
}

func init() {
	proto.RegisterType((*Block)(nil), "roothash.Block")
	proto.RegisterType((*Nonce)(nil), "roothash.Nonce")
	proto.RegisterType((*Header)(nil), "roothash.Header")
	proto.RegisterType((*LatestBlockRequest)(nil), "roothash.LatestBlockRequest")
	proto.RegisterType((*LatestBlockResponse)(nil), "roothash.LatestBlockResponse")
	proto.RegisterType((*BlockRequest)(nil), "roothash.BlockRequest")
	proto.RegisterType((*BlockResponse)(nil), "roothash.BlockResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// RootHashClient is the client API for RootHash service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type RootHashClient interface {
	GetLatestBlock(ctx context.Context, in *LatestBlockRequest, opts ...grpc.CallOption) (*LatestBlockResponse, error)
	GetBlocks(ctx context.Context, in *BlockRequest, opts ...grpc.CallOption) (RootHash_GetBlocksClient, error)
}

type rootHashClient struct {
	cc *grpc.ClientConn
}

func NewRootHashClient(cc *grpc.ClientConn) RootHashClient {
	return &rootHashClient{cc}
}

func (c *rootHashClient) GetLatestBlock(ctx context.Context, in *LatestBlockRequest, opts ...grpc.CallOption) (*LatestBlockResponse, error) {
	out := new(LatestBlockResponse)
	err := c.cc.Invoke(ctx, "/roothash.RootHash/GetLatestBlock", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *rootHashClient) GetBlocks(ctx context.Context, in *BlockRequest, opts ...grpc.CallOption) (RootHash_GetBlocksClient, error) {
	stream, err := c.cc.NewStream(ctx, &_RootHash_serviceDesc.Streams[0], "/roothash.RootHash/GetBlocks", opts...)
	if err != nil {
		return nil, err
	}
	x := &rootHashGetBlocksClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type RootHash_GetBlocksClient interface {
	Recv() (*BlockResponse, error)
	grpc.ClientStream
}

type rootHashGetBlocksClient struct {
	grpc.ClientStream
}

func (x *rootHashGetBlocksClient) Recv() (*BlockResponse, error) {
	m := new(BlockResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// RootHashServer is the server API for RootHash service.
type RootHashServer interface {
	GetLatestBlock(context.Context, *LatestBlockRequest) (*LatestBlockResponse, error)
	GetBlocks(*BlockRequest, RootHash_GetBlocksServer) error
}

func RegisterRootHashServer(s *grpc.Server, srv RootHashServer) {
	s.RegisterService(&_RootHash_serviceDesc, srv)
}

func _RootHash_GetLatestBlock_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LatestBlockRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RootHashServer).GetLatestBlock(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/roothash.RootHash/GetLatestBlock",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RootHashServer).GetLatestBlock(ctx, req.(*LatestBlockRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RootHash_GetBlocks_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(BlockRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(RootHashServer).GetBlocks(m, &rootHashGetBlocksServer{stream})
}

type RootHash_GetBlocksServer interface {
	Send(*BlockResponse) error
	grpc.ServerStream
}

type rootHashGetBlocksServer struct {
	grpc.ServerStream
}

func (x *rootHashGetBlocksServer) Send(m *BlockResponse) error {
	return x.ServerStream.SendMsg(m)
}

var _RootHash_serviceDesc = grpc.ServiceDesc{
	ServiceName: "roothash.RootHash",
	HandlerType: (*RootHashServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetLatestBlock",
			Handler:    _RootHash_GetLatestBlock_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GetBlocks",
			Handler:       _RootHash_GetBlocks_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "roothash/roothash.proto",
}

func init() { proto.RegisterFile("roothash/roothash.proto", fileDescriptor_roothash_ea8a28a424a3bb97) }

var fileDescriptor_roothash_ea8a28a424a3bb97 = []byte{
	// 490 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x93, 0x4d, 0x6f, 0xd4, 0x3e,
	0x10, 0xc6, 0xff, 0xfb, 0x67, 0x5f, 0x67, 0xdf, 0x2a, 0x83, 0x68, 0x80, 0x56, 0xad, 0x82, 0x10,
	0x8b, 0x04, 0x1b, 0x68, 0x25, 0x4e, 0x1c, 0x50, 0x2f, 0x2d, 0x12, 0x02, 0x29, 0xe2, 0xc4, 0x25,
	0xf2, 0x26, 0xa3, 0xc4, 0x6a, 0x13, 0x1b, 0x7b, 0x52, 0xa9, 0x1f, 0x86, 0x33, 0x5f, 0x13, 0x65,
	0x9c, 0xec, 0x16, 0x2a, 0x0e, 0x70, 0x8b, 0x7f, 0xcf, 0x3c, 0x33, 0x8f, 0x26, 0x36, 0xec, 0x5b,
	0xad, 0xa9, 0x90, 0xae, 0x88, 0xba, 0x8f, 0xb5, 0xb1, 0x9a, 0xb4, 0x18, 0x77, 0xe7, 0xf0, 0x0d,
	0x0c, 0xce, 0xae, 0x74, 0x7a, 0x29, 0x56, 0x30, 0x2c, 0x50, 0x66, 0x68, 0x83, 0xde, 0x71, 0x6f,
	0x35, 0x3d, 0xd9, 0x5b, 0x6f, 0x3d, 0x17, 0xcc, 0xe3, 0x56, 0x0f, 0x9f, 0xc0, 0xe0, 0x93, 0xae,
	0x52, 0x14, 0x02, 0xfa, 0x99, 0x24, 0xc9, 0x86, 0x59, 0xcc, 0xdf, 0xe1, 0x8f, 0x7b, 0x30, 0xf4,
	0xf5, 0x22, 0x80, 0xd1, 0x35, 0x5a, 0xa7, 0x74, 0xc5, 0x15, 0xf3, 0xb8, 0x3b, 0x8a, 0x03, 0x98,
	0x54, 0xb2, 0x44, 0x67, 0x64, 0x8a, 0xc1, 0xff, 0xec, 0xde, 0x81, 0x46, 0x25, 0x55, 0xa2, 0x23,
	0x59, 0x9a, 0xa0, 0x7f, 0xdc, 0x5b, 0xf5, 0xe3, 0x1d, 0x10, 0x47, 0x30, 0xf5, 0x39, 0x12, 0xba,
	0x31, 0x18, 0x0c, 0xb8, 0x33, 0x78, 0xf4, 0xe5, 0xc6, 0xa0, 0x78, 0x0a, 0x73, 0x63, 0xf1, 0x5a,
	0xe9, 0xda, 0x25, 0x4d, 0xfc, 0x60, 0xc8, 0x03, 0x66, 0x1d, 0xbc, 0x90, 0xae, 0x10, 0x87, 0x00,
	0xb9, 0xd5, 0xb5, 0xf1, 0x15, 0x23, 0x1f, 0x81, 0x49, 0x27, 0xab, 0xca, 0xd4, 0xe4, 0xe5, 0xb1,
	0x97, 0x99, 0xb0, 0x7c, 0x04, 0x53, 0x5d, 0xd3, 0x56, 0x9f, 0xb0, 0x0e, 0x1e, 0x75, 0x7e, 0x47,
	0x92, 0x30, 0x69, 0x76, 0x18, 0x80, 0xf7, 0x33, 0x89, 0xb5, 0x26, 0xf1, 0x02, 0xf6, 0x52, 0x5d,
	0x96, 0x8a, 0x4a, 0xac, 0xa8, 0x4d, 0x39, 0xe5, 0xa2, 0xe5, 0x2d, 0xce, 0x9d, 0x9e, 0xc3, 0xd2,
	0x91, 0xb6, 0x32, 0xc7, 0xc4, 0x62, 0x8a, 0xca, 0x50, 0x30, 0xe3, 0xca, 0x45, 0x8b, 0x63, 0x4f,
	0xc5, 0x03, 0x18, 0x58, 0x5d, 0x57, 0x59, 0x30, 0xe7, 0x8d, 0xf9, 0x83, 0x78, 0x04, 0x63, 0x92,
	0xb9, 0x9f, 0xb0, 0x60, 0xdf, 0x88, 0x64, 0xde, 0x74, 0x0e, 0x4f, 0x41, 0x7c, 0x94, 0x84, 0x8e,
	0xf8, 0xff, 0xc7, 0xf8, 0xad, 0x46, 0x47, 0x4d, 0x72, 0x5b, 0x57, 0xcd, 0xba, 0x13, 0x95, 0xb5,
	0x7f, 0x76, 0xd2, 0x92, 0x0f, 0x59, 0xf8, 0x0e, 0xee, 0xff, 0x62, 0x72, 0x46, 0x57, 0x0e, 0xc5,
	0x33, 0x18, 0x6c, 0x1a, 0xd0, 0xde, 0x9d, 0xe5, 0xee, 0xee, 0xf8, 0x3a, 0xaf, 0x86, 0xaf, 0x60,
	0xf6, 0x37, 0xc3, 0xde, 0xc2, 0xfc, 0x5f, 0xc6, 0x9c, 0x7c, 0xef, 0xc1, 0xb8, 0xd9, 0x33, 0x2f,
	0xf0, 0x33, 0x2c, 0xce, 0x91, 0x6e, 0x85, 0x16, 0x07, 0x3b, 0xdb, 0xdd, 0x05, 0x3c, 0x3e, 0xfc,
	0x83, 0xea, 0x23, 0x84, 0xff, 0x89, 0xf7, 0x30, 0x39, 0x47, 0x4f, 0x9d, 0x78, 0xf8, 0x7b, 0x84,
	0xb6, 0xcb, 0xfe, 0x1d, 0xde, 0xf9, 0x5f, 0xf7, 0xce, 0xd6, 0x5f, 0x5f, 0xe6, 0x8a, 0x8a, 0x7a,
	0xb3, 0x4e, 0x75, 0x19, 0x69, 0xe9, 0x94, 0xbb, 0x92, 0x1b, 0x17, 0xe1, 0xa5, 0xca, 0xb0, 0x8a,
	0x72, 0x1d, 0xe5, 0xd6, 0xa4, 0xdb, 0x37, 0xbb, 0x19, 0xf2, 0xa3, 0x3d, 0xfd, 0x19, 0x00, 0x00,
	0xff, 0xff, 0x80, 0x59, 0xd8, 0x47, 0xcf, 0x03, 0x00, 0x00,
}
