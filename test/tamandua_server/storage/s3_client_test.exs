defmodule TamanduaServer.Storage.S3ClientTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Storage.S3Client

  @moduledoc """
  Unit tests for S3Client module.

  These tests verify the module interface and behavior without requiring
  actual S3 connectivity. Integration tests with MinIO are in
  test/integration/s3_integration_test.exs.
  """

  describe "module interface" do
    test "exports upload/3" do
      assert function_exported?(S3Client, :upload, 3)
    end

    test "exports download/2" do
      assert function_exported?(S3Client, :download, 2)
    end

    test "exports delete/2" do
      assert function_exported?(S3Client, :delete, 2)
    end

    test "exports presigned_url/3" do
      assert function_exported?(S3Client, :presigned_url, 3)
    end

    test "exports exists?/1" do
      assert function_exported?(S3Client, :exists?, 1)
    end

    test "exports list/2" do
      assert function_exported?(S3Client, :list, 2)
    end

    test "exports head/1" do
      assert function_exported?(S3Client, :head, 1)
    end

    test "exports copy/3" do
      assert function_exported?(S3Client, :copy, 3)
    end

    test "exports delete_multiple/1" do
      assert function_exported?(S3Client, :delete_multiple, 1)
    end
  end

  describe "presigned_url/3" do
    test "generates presigned URL for GET" do
      result = S3Client.presigned_url("test/file.txt", :get, expires_in: 3600)
      assert {:ok, url} = result
      assert is_binary(url)
      assert String.contains?(url, "test/file.txt")
    end

    test "generates presigned URL for PUT" do
      result = S3Client.presigned_url("test/file.txt", :put, expires_in: 3600)
      assert {:ok, url} = result
      assert is_binary(url)
    end

    test "accepts custom expiration" do
      {:ok, url} = S3Client.presigned_url("test/file.txt", :get, expires_in: 7200)
      assert is_binary(url)
    end
  end
end
