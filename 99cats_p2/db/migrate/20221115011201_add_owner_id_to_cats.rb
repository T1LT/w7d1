class AddOwnerIdToCats < ActiveRecord::Migration[7.0]
  def change
    add_column :cats, :owner_id, :bigint
    add_index :cats, :owner_id
    add_foreign_key :cats, :users, column: :owner_id
  end
end
