defmodule TamanduaServer.Dashboard do
  @moduledoc """
  The Dashboard context.
  Provides functions for dashboard sharing and analytics.
  """

  alias TamanduaServer.Dashboard.ShareManager

  # Delegate sharing functions to ShareManager
  defdelegate list_shares_for_dashboard(dashboard_layout_id), to: ShareManager
  defdelegate list_shares_by_user(user_id), to: ShareManager
  defdelegate get_share_by_token(token), to: ShareManager
  defdelegate get_share(id), to: ShareManager
  defdelegate create_share(attrs), to: ShareManager
  defdelegate update_share(share, attrs), to: ShareManager
  defdelegate delete_share(share), to: ShareManager
  defdelegate revoke_share(share), to: ShareManager
  defdelegate activate_share(share), to: ShareManager
  defdelegate toggle_active(share), to: ShareManager
  defdelegate update_last_accessed(share), to: ShareManager
  defdelegate regenerate_token(share), to: ShareManager

  # Access validation
  defdelegate validate_access(share_token, opts \\ []), to: ShareManager

  # Analytics
  defdelegate record_view(dashboard_share_id, attrs), to: ShareManager
  defdelegate record_view_from_conn(conn, dashboard_share_id, session_id \\ nil), to: ShareManager
  defdelegate get_share_analytics(share_id, opts \\ []), to: ShareManager
  defdelegate get_user_analytics(user_id, opts \\ []), to: ShareManager

  # Bulk operations
  defdelegate revoke_all_shares_for_dashboard(dashboard_layout_id), to: ShareManager
  defdelegate cleanup_expired_shares(), to: ShareManager
end
